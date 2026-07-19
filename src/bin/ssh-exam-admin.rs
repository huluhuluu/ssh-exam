use std::{io::Read, path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ssh_exam_gate::{
    config::{AdminAuthConfig, AppConfig},
    db::Db,
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
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    Migrate {
        #[arg(long)]
        config: PathBuf,
    },
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
            Db::new(&config.database_path, config.busy_timeout()).initialize()?;
            Ok(())
        }
        Command::HashPassword => {
            let mut password = Vec::new();
            std::io::stdin()
                .take(1025)
                .read_to_end(&mut password)
                .context("failed to read password from stdin")?;
            while matches!(password.last(), Some(b'\n' | b'\r')) {
                password.pop();
            }
            println!("{}", web::hash_password(&password)?);
            Ok(())
        }
    }
}

async fn serve(config_path: PathBuf) -> Result<()> {
    let config = AppConfig::load(&config_path)?;
    let auth = AdminAuthConfig::load(&config.admin_auth_path)?;
    let db = Db::new(&config.database_path, config.busy_timeout());
    db.initialize()?;
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

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
