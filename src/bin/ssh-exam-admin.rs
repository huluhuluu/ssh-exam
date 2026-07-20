use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use ssh_exam_gate::{
    config::{AdminAuthConfig, AppConfig},
    db::{Db, TestDefinitionInput},
    quiz::{CompositionOptions, Quiz, QuizCatalog},
    web::{self, WebState},
};

#[derive(Debug, Parser)]
#[command(version, about = "Loopback administration server for SSH Exam Gate")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the loopback administration server / 启动本地管理服务
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Apply database migrations and seed the legacy test / 执行迁移并初始化兼容测试
    Migrate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Initialize the database and administrator authentication / 初始化数据库和管理员认证
    Init {
        #[arg(long)]
        config: PathBuf,
    },
    /// Replace the administrator password from standard input / 从标准输入修改管理员密码
    SetAdminPassword {
        #[arg(long)]
        config: PathBuf,
    },
    /// Import a validated JSON question bank / 导入并校验 JSON 题库
    ImportBank {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// List question banks / 查看题库
    ListBanks {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a test from comma-separated bank IDs / 从多个题库创建测试
    CreateTest {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        title: String,
        #[arg(long, value_delimiter = ',')]
        banks: Vec<String>,
        #[arg(long, default_value_t = 80)]
        pass_threshold: u32,
        #[arg(long, default_value_t = 3)]
        max_attempts: u32,
        #[arg(long)]
        question_limit: Option<u32>,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        shuffle_questions: bool,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        shuffle_choices: bool,
    },
    /// List saved tests / 查看测试
    ListTests {
        #[arg(long)]
        config: PathBuf,
    },
    /// Publish a saved test / 发布测试
    PublishTest {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// List immutable publications for a test / 查看测试发布历史
    ListPublications {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// Activate an immutable prior publication / 启用历史发布版本
    ActivatePublication {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        publication_id: i64,
    },
    /// Show the active immutable test revision / 查看当前发布版本
    ShowPublishedTest {
        #[arg(long)]
        config: PathBuf,
    },
    /// Hash a password from standard input / 对标准输入密码生成哈希
    HashPassword,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Arguments::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ssh-exam-admin: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(arguments: Arguments) -> Result<()> {
    match arguments.command {
        Command::Serve { config } => serve(config).await,
        Command::Migrate { config } => {
            let config = AppConfig::load(&config)?;
            let db = initialized_db(&config)?;
            db.ensure_legacy_test(&Quiz::load(&config.quiz_path)?)?;
            Ok(())
        }
        Command::Init { config } => {
            let config = AppConfig::load(&config)?;
            if config.admin_auth_path.exists() {
                bail!(
                    "admin auth file already exists; use set-admin-password / 管理员认证文件已存在，请使用 set-admin-password"
                );
            }
            let db = initialized_db(&config)?;
            db.ensure_legacy_test(&Quiz::load(&config.quiz_path)?)?;
            write_admin_auth(&config.admin_auth_path, read_password()?, None)?;
            println!("initialized / 初始化完成");
            Ok(())
        }
        Command::SetAdminPassword { config } => {
            let config = AppConfig::load(&config)?;
            let existing = AdminAuthConfig::load(&config.admin_auth_path)?;
            write_admin_auth(&config.admin_auth_path, read_password()?, Some(existing))?;
            println!("administrator password updated / 管理员密码已更新");
            Ok(())
        }
        Command::ImportBank { config, id, file } => {
            let config = AppConfig::load(&config)?;
            let raw = fs::read(&file)
                .with_context(|| format!("failed to read question bank {}", file.display()))?;
            let catalog = QuizCatalog::new(config.quiz_path, config.quiz_directory);
            catalog.ensure_writable()?;
            let bank = catalog.import(&id, &raw)?;
            println!(
                "{}\t{}\t{} questions",
                bank.id,
                bank.quiz.title,
                bank.quiz.questions.len()
            );
            Ok(())
        }
        Command::ListBanks { config } => {
            let config = AppConfig::load(&config)?;
            let catalog = QuizCatalog::new(config.quiz_path, config.quiz_directory);
            for bank in catalog.discover()? {
                println!(
                    "{}\t{}\t{}\t{} questions",
                    bank.id,
                    bank.quiz.title,
                    bank.quiz.environment.as_str(),
                    bank.quiz.questions.len()
                );
            }
            Ok(())
        }
        Command::CreateTest {
            config,
            id,
            title,
            banks,
            pass_threshold,
            max_attempts,
            question_limit,
            shuffle_questions,
            shuffle_choices,
        } => {
            let config = AppConfig::load(&config)?;
            let db = initialized_db(&config)?;
            let catalog = QuizCatalog::new(config.quiz_path, config.quiz_directory);
            catalog.compose(
                title.clone(),
                &banks,
                CompositionOptions {
                    pass_threshold_percent: pass_threshold,
                    max_attempts,
                    question_limit,
                    shuffle_questions,
                    shuffle_choices,
                },
            )?;
            db.create_test(&TestDefinitionInput {
                id: id.clone(),
                title,
                bank_ids: banks,
                pass_threshold_percent: pass_threshold,
                max_attempts,
                question_limit,
                shuffle_questions,
                shuffle_choices,
            })?;
            println!("test created: {id} / 测试已创建");
            Ok(())
        }
        Command::ListTests { config } => {
            let config = AppConfig::load(&config)?;
            let db = initialized_db(&config)?;
            let active = db.published_test()?;
            for test in db.list_tests()? {
                let marker = if active.as_ref().is_some_and(|item| item.test_id == test.id) {
                    "published"
                } else {
                    "draft"
                };
                println!(
                    "{}\t{}\t{}\t{} banks\t{}% threshold",
                    test.id,
                    marker,
                    test.title,
                    test.bank_ids.len(),
                    test.pass_threshold_percent
                );
            }
            Ok(())
        }
        Command::PublishTest { config, id } => {
            let config = AppConfig::load(&config)?;
            let db = initialized_db(&config)?;
            let test = db.get_test(&id)?;
            let catalog = QuizCatalog::new(config.quiz_path, config.quiz_directory);
            let quiz = catalog.compose(
                test.title,
                &test.bank_ids,
                CompositionOptions {
                    pass_threshold_percent: test.pass_threshold_percent,
                    max_attempts: test.max_attempts,
                    question_limit: test.question_limit,
                    shuffle_questions: test.shuffle_questions,
                    shuffle_choices: test.shuffle_choices,
                },
            )?;
            let published = db.publish_test(&id, &quiz)?;
            println!("{}\t{}", published.test_id, published.revision);
            Ok(())
        }
        Command::ListPublications { config, id } => {
            let config = AppConfig::load(&config)?;
            let db = initialized_db(&config)?;
            for publication in db.list_publications(&id)? {
                println!(
                    "{}\t{}\t{}\t{} questions\t{} UTC",
                    publication.publication_id,
                    if publication.active {
                        "active"
                    } else {
                        "history"
                    },
                    publication.revision,
                    publication
                        .quiz
                        .question_limit
                        .unwrap_or(publication.quiz.questions.len() as u32),
                    publication.published_at
                );
            }
            Ok(())
        }
        Command::ActivatePublication {
            config,
            id,
            publication_id,
        } => {
            let config = AppConfig::load(&config)?;
            let db = initialized_db(&config)?;
            let published = db.activate_publication(&id, publication_id)?;
            println!("{}\t{}", published.test_id, published.revision);
            Ok(())
        }
        Command::ShowPublishedTest { config } => {
            let config = AppConfig::load(&config)?;
            let db = initialized_db(&config)?;
            let published = db
                .published_test()?
                .context("no test is currently published / 当前没有已发布测试")?;
            println!(
                "{}\t{}\t{}\t{} questions",
                published.test_id,
                published.revision,
                published.quiz.title,
                published
                    .quiz
                    .question_limit
                    .unwrap_or(published.quiz.questions.len() as u32)
            );
            Ok(())
        }
        Command::HashPassword => {
            println!("{}", web::hash_password(&read_password()?)?);
            Ok(())
        }
    }
}

async fn serve(config_path: PathBuf) -> Result<()> {
    let config = AppConfig::load(&config_path)?;
    let auth = AdminAuthConfig::load(&config.admin_auth_path)?;
    let db = initialized_db(&config)?;
    db.ensure_legacy_test(&Quiz::load(&config.quiz_path)?)?;
    let state = WebState::new_with_catalog(
        db,
        config.quiz_path.clone(),
        config.quiz_directory.clone(),
        &auth,
    )?;
    let listener = tokio::net::TcpListener::bind(config.admin_bind)
        .await
        .with_context(|| format!("failed to bind admin server to {}", config.admin_bind))?;
    println!("ssh-exam-admin listening on http://{}", config.admin_bind);
    axum::serve(listener, web::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("admin server failed")
}

fn initialized_db(config: &AppConfig) -> Result<Db> {
    let db = Db::new(&config.database_path, config.busy_timeout());
    db.initialize()?;
    Ok(db)
}

fn read_password() -> Result<Vec<u8>> {
    let mut password = Vec::new();
    std::io::stdin()
        .take(1025)
        .read_to_end(&mut password)
        .context("failed to read password from stdin")?;
    while matches!(password.last(), Some(b'\n' | b'\r')) {
        password.pop();
    }
    if password.is_empty() || password.len() > 1024 {
        bail!("password must contain between 1 and 1024 bytes");
    }
    Ok(password)
}

fn write_admin_auth(
    path: &Path,
    password: Vec<u8>,
    existing: Option<AdminAuthConfig>,
) -> Result<()> {
    let session_ttl_seconds = existing
        .map(|config| config.session_ttl_seconds)
        .unwrap_or(8 * 60 * 60);
    let mut secret = [0_u8; 32];
    OsRng.fill_bytes(&mut secret);
    let auth = AdminAuthConfig {
        password_hash: web::hash_password(&password)?,
        session_secret_base64: STANDARD.encode(secret),
        session_ttl_seconds,
    };
    auth.validate()?;
    let mut encoded = serde_json::to_vec_pretty(&auth)?;
    encoded.push(b'\n');
    let parent = path
        .parent()
        .context("administrator authentication path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(
        ".admin-auth-{}.tmp",
        URL_SAFE_NO_PAD.encode(random)
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file: File = options
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        drop(file);
        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(path)
                .with_context(|| format!("failed to replace {}", path.display()))?;
        }
        fs::rename(&temporary, path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
