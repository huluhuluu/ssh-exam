use std::path::Path;

use anyhow::{bail, Result};

use crate::{
    config::AppConfig,
    db::{Db, PolicyRecord},
    keys::{fingerprint, validate_fingerprint, validate_key_type},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Deny,
    Pending(String),
    Passed(String),
}

impl PolicyDecision {
    pub fn authorized_keys_line(&self) -> Option<&str> {
        match self {
            Self::Deny => None,
            Self::Pending(line) | Self::Passed(line) => Some(line),
        }
    }
}

pub fn evaluate(
    db: &Db,
    config: &AppConfig,
    config_path: &Path,
    unix_username: &str,
    supplied_fingerprint: &str,
    supplied_key_type: &str,
    supplied_key_base64: &str,
) -> Result<PolicyDecision> {
    if validate_fingerprint(supplied_fingerprint).is_err()
        || validate_key_type(supplied_key_type).is_err()
        || fingerprint(supplied_key_base64).ok().as_deref() != Some(supplied_fingerprint)
    {
        return Ok(PolicyDecision::Deny);
    }
    let Some(record) = db.resolve_policy(unix_username, supplied_fingerprint)? else {
        return Ok(PolicyDecision::Deny);
    };
    if record.fingerprint != supplied_fingerprint
        || record.key_type != supplied_key_type
        || record.key_base64 != supplied_key_base64
    {
        return Ok(PolicyDecision::Deny);
    }
    render_record(config, config_path, &record)
}

fn render_record(
    config: &AppConfig,
    config_path: &Path,
    record: &PolicyRecord,
) -> Result<PolicyDecision> {
    let registered_key = format!("{} {} ssh-exam-gate", record.key_type, record.key_base64);
    if !record.passed {
        let command = format!(
            "{} -n -u {} -- {} --config {} --username {} --fingerprint {} --language {}",
            shell_word(&config.sudo_path)?,
            shell_value(&config.tui_run_as)?,
            shell_word(&config.tui_path)?,
            shell_word(config_path)?,
            shell_value(&record.unix_username)?,
            shell_value(&record.fingerprint)?,
            shell_value(&config.tui_language)?,
        );
        return Ok(PolicyDecision::Pending(format!(
            "restrict,pty,command={} {}",
            authorized_option(&command)?,
            registered_key
        )));
    }
    Ok(PolicyDecision::Passed(registered_key))
}

fn authorized_option(value: &str) -> Result<String> {
    if value
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
    {
        bail!("authorized_keys option contains a control character");
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn shell_word(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("command path is not UTF-8"))?;
    shell_value(value)
}

fn shell_value(value: &str) -> Result<String> {
    if value
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
    {
        bail!("shell argument contains a control character");
    }
    Ok(format!("'{}'", value.replace('\'', "'\"'\"'")))
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::PathBuf, time::Duration};

    use tempfile::TempDir;

    use super::*;
    use crate::{
        db::{AttemptInput, KeyRecord},
        quiz::{Question, Quiz},
    };

    const KEY: &str = "ssh-ed25519 aGVsbG8= ignored-comment";

    fn config(directory: &TempDir) -> AppConfig {
        AppConfig {
            database_path: directory.path().join("gate.db"),
            quiz_path: PathBuf::from("/etc/ssh-exam/quiz.json"),
            quiz_directory: None,
            tui_path: PathBuf::from("/usr/local/libexec/ssh-exam-tui"),
            tui_run_as: "ssh-exam-tui".to_owned(),
            sudo_path: PathBuf::from("/usr/bin/sudo"),
            tui_language: "bilingual".to_owned(),
            legacy_proxy_refuse_command: None,
            admin_bind: "127.0.0.1:8787".parse::<SocketAddr>().unwrap(),
            admin_auth_path: PathBuf::from("/etc/ssh-exam/admin-auth.json"),
            busy_timeout_ms: 1_000,
        }
    }

    fn setup() -> (TempDir, Db, AppConfig, KeyRecord, i64) {
        let directory = TempDir::new().unwrap();
        let config = config(&directory);
        let db = Db::new(&config.database_path, Duration::from_secs(1));
        db.initialize().unwrap();
        db.ensure_legacy_test(&Quiz {
            title: "Safety".to_owned(),
            environment: Default::default(),
            pass_threshold_percent: 80,
            max_attempts: 3,
            question_limit: None,
            shuffle_questions: true,
            shuffle_choices: true,
            questions: vec![Question {
                prompt: "Ready?".to_owned(),
                choices: vec!["Yes".to_owned(), "No".to_owned()],
                correct_index: 0,
            }],
        })
        .unwrap();
        let person = db.create_person("Alice", Some("root")).unwrap();
        let key = db.add_key(person, KEY).unwrap();
        (directory, db, config, key, person)
    }

    #[test]
    fn unknown_mismatch_and_disabled_all_deny_without_output() {
        let (_directory, db, config, key, _) = setup();
        let config_path = Path::new("/etc/ssh-exam/config.json");
        for decision in [
            evaluate(
                &db,
                &config,
                config_path,
                "nobody",
                &key.fingerprint,
                &key.key_type,
                &key.key_base64,
            )
            .unwrap(),
            evaluate(
                &db,
                &config,
                config_path,
                "root",
                &key.fingerprint,
                "ssh-rsa",
                &key.key_base64,
            )
            .unwrap(),
            evaluate(
                &db,
                &config,
                config_path,
                "root",
                "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                &key.key_type,
                &key.key_base64,
            )
            .unwrap(),
        ] {
            assert_eq!(decision, PolicyDecision::Deny);
            assert!(decision.authorized_keys_line().is_none());
        }
    }

    #[test]
    fn pending_line_has_exact_forced_exam_restrictions() {
        let (_directory, db, config, key, _) = setup();
        let decision = evaluate(
            &db,
            &config,
            Path::new("/etc/ssh-exam/config.json"),
            "root",
            &key.fingerprint,
            &key.key_type,
            &key.key_base64,
        )
        .unwrap();
        assert_eq!(
            decision,
            PolicyDecision::Pending(format!(
                "restrict,pty,command=\"'/usr/bin/sudo' -n -u 'ssh-exam-tui' -- '/usr/local/libexec/ssh-exam-tui' --config '/etc/ssh-exam/config.json' --username 'root' --fingerprint '{}' --language 'bilingual'\" ssh-ed25519 aGVsbG8= ssh-exam-gate",
                key.fingerprint
            ))
        );
    }

    #[test]
    fn passed_identity_has_no_forced_command_or_options() {
        let (_directory, db, config, key, person) = setup();
        pass(&db, person);
        let decision = evaluate(
            &db,
            &config,
            Path::new("/etc/ssh-exam/config.json"),
            "root",
            &key.fingerprint,
            &key.key_type,
            &key.key_base64,
        )
        .unwrap();
        assert_eq!(
            decision.authorized_keys_line(),
            Some("ssh-ed25519 aGVsbG8= ssh-exam-gate")
        );
    }

    #[test]
    fn disabled_key_denies_at_policy_boundary() {
        let (_directory, db, config, key, _) = setup();
        db.set_key_enabled(key.id, false).unwrap();
        let decision = evaluate(
            &db,
            &config,
            Path::new("/etc/ssh-exam/config.json"),
            "root",
            &key.fingerprint,
            &key.key_type,
            &key.key_base64,
        )
        .unwrap();
        assert_eq!(decision, PolicyDecision::Deny);
    }

    fn pass(db: &Db, person_id: i64) {
        let published = db.published_test().unwrap().unwrap();
        db.record_attempt(&AttemptInput {
            person_id,
            test_id: &published.test_id,
            revision: &published.revision,
            score: 1,
            total: 1,
            passed: true,
            answers_json: "[0]",
            max_attempts: 3,
        })
        .unwrap();
    }
}
