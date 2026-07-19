use std::path::Path;

use ssh_exam_gate::{
    config::{AdminAuthConfig, AppConfig},
    quiz::{Quiz, QuizCatalog},
};

#[test]
fn shipped_json_examples_match_the_application_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    AppConfig::load(&root.join("examples/config.example.json")).unwrap();
    AdminAuthConfig::load(&root.join("examples/admin-auth.example.json")).unwrap();
    Quiz::load(&root.join("examples/quiz.example.json")).unwrap();
    let catalog = QuizCatalog::new(
        root.join("examples/quiz.example.json"),
        Some(root.join("examples/banks")),
    );
    let ids = catalog
        .discover()
        .unwrap()
        .into_iter()
        .map(|bank| bank.id)
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec!["legacy", "docker-ssh", "host-ssh", "network-topology"]
    );
}

#[test]
fn legacy_config_omitting_catalog_and_language_still_loads() {
    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
          "database_path":"/var/lib/ssh-exam/gate.db",
          "quiz_path":"/var/lib/ssh-exam/quiz.json",
          "tui_path":"/usr/local/libexec/ssh-exam-tui",
          "admin_auth_path":"/etc/ssh-exam/admin-auth.json"
        }"#,
    )
    .unwrap();
    let config = AppConfig::load(&path).unwrap();
    assert!(config.quiz_directory.is_none());
    assert_eq!(config.tui_language, "bilingual");
}
