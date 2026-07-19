use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};

use ssh_exam_gate::{
    config::AppConfig,
    db::{AccessMode, BindingInput, Db},
    quiz::{BankEnvironment, Question, Quiz, QuizCatalog, LEGACY_BANK_ID},
};
use tempfile::TempDir;

const POLICY: &str = env!("CARGO_BIN_EXE_ssh-exam-key-policy");
const TUI: &str = env!("CARGO_BIN_EXE_ssh-exam-tui");
const ADMIN: &str = env!("CARGO_BIN_EXE_ssh-exam-admin");

fn test_config(directory: &TempDir) -> (std::path::PathBuf, AppConfig) {
    let path = directory.path().join("config.json");
    let config = AppConfig {
        database_path: directory.path().join("gate.db"),
        quiz_path: directory.path().join("quiz.json"),
        quiz_directory: None,
        tui_path: "/usr/local/libexec/ssh-exam-tui".into(),
        tui_run_as: "ssh-exam-tui".to_owned(),
        sudo_path: "/usr/bin/sudo".into(),
        tui_language: "bilingual".to_owned(),
        proxy_refuse_command: "/usr/sbin/nologin".into(),
        admin_bind: "127.0.0.1:8787".parse().unwrap(),
        admin_auth_path: directory.path().join("admin-auth.json"),
        busy_timeout_ms: 1_000,
    };
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    (path, config)
}

#[test]
fn required_cli_arguments_fail_with_nonzero_status() {
    for binary in [POLICY, TUI, ADMIN] {
        let output = Command::new(binary).output().unwrap();
        assert!(
            !output.status.success(),
            "{binary} accepted missing arguments"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn policy_unknown_key_is_successful_with_exactly_no_output() {
    let directory = TempDir::new().unwrap();
    let (config_path, config) = test_config(&directory);
    let db = Db::new(&config.database_path, Duration::from_secs(1));
    db.initialize().unwrap();
    let output = Command::new(POLICY)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--username",
            "root",
            "--fingerprint",
            "SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
            "--key-type",
            "ssh-ed25519",
            "--key-base64",
            "aGVsbG8=",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn policy_internal_error_is_generic_and_does_not_echo_identity() {
    let output = Command::new(POLICY)
        .args([
            "--config",
            "/definitely/missing/ssh-exam.json",
            "--username",
            "sensitive-user",
            "--fingerprint",
            "SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
            "--key-type",
            "ssh-ed25519",
            "--key-base64",
            "aGVsbG8=",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr, "ssh-exam-key-policy: internal policy error\n");
    assert!(!stderr.contains("sensitive-user"));
}

#[test]
fn tui_rejects_sudo_user_mismatch_before_database_access() {
    let output = Command::new(TUI)
        .env("SUDO_USER", "nobody")
        .args([
            "--config",
            "/definitely/missing/ssh-exam.json",
            "--username",
            "root",
            "--fingerprint",
            "SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ",
            "--bank",
            "legacy",
            "--language",
            "zh",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "ssh-exam-tui: session identity validation failed\n"
    );
}

#[test]
fn tui_rejects_bank_that_does_not_match_the_mapping() {
    let directory = TempDir::new().unwrap();
    let (config_path, mut config) = test_config(&directory);
    let banks_path = directory.path().join("banks");
    fs::create_dir(&banks_path).unwrap();
    config.quiz_directory = Some(banks_path.clone());
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let quiz = Quiz {
        title: "Test bank".to_owned(),
        environment: BankEnvironment::General,
        pass_threshold_percent: 80,
        max_attempts: 3,
        questions: vec![Question {
            prompt: "Ready?".to_owned(),
            choices: vec!["Yes".to_owned(), "No".to_owned()],
            correct_index: 0,
        }],
    };
    quiz.save_atomic(&config.quiz_path).unwrap();
    QuizCatalog::new(&config.quiz_path, Some(banks_path))
        .create("host-ssh", &quiz)
        .unwrap();
    let db = Db::new(&config.database_path, Duration::from_secs(1));
    db.initialize().unwrap();
    let person = db.create_person("Bank CLI Test").unwrap();
    let key = db
        .add_key(person, "ssh-ed25519 aGVsbG8= test-device")
        .unwrap();
    db.add_binding(&BindingInput {
        person_id: person,
        ssh_key_id: None,
        unix_username: "root".to_owned(),
        access_mode: AccessMode::Shell,
        permitopen: vec![],
        bank_id: LEGACY_BANK_ID.to_owned(),
    })
    .unwrap();

    let output = Command::new(TUI)
        .env("SUDO_USER", "root")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--username",
            "root",
            "--fingerprint",
            &key.fingerprint,
            "--bank",
            "host-ssh",
            "--language",
            "en",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "ssh-exam-tui: session bank validation failed\n"
    );
}

#[test]
fn admin_hashes_stdin_password_and_migrates_database() {
    let mut child = Command::new(ADMIN)
        .arg("hash-password")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"unit-test-admin-input\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let hash = String::from_utf8(output.stdout).unwrap();
    assert!(hash.starts_with("$argon2"));

    let directory = TempDir::new().unwrap();
    let (config_path, config) = test_config(&directory);
    let output = Command::new(ADMIN)
        .args(["migrate", "--config", config_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(config.database_path.exists());
}
