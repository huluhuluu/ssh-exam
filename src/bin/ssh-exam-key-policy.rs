use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use ssh_exam_gate::{config::AppConfig, db::Db, policy};

#[derive(Debug, Parser)]
#[command(version, about = "OpenSSH AuthorizedKeysCommand policy helper")]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    username: String,
    #[arg(long)]
    fingerprint: String,
    #[arg(long = "key-type")]
    key_type: String,
    #[arg(long = "key-base64")]
    key_base64: String,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match run(&arguments) {
        Ok(Some(line)) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("ssh-exam-key-policy: internal policy error");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &Arguments) -> Result<Option<String>, ()> {
    let config = AppConfig::load(&arguments.config).map_err(|_| ())?;
    let db = Db::new(&config.database_path, config.busy_timeout());
    let decision = policy::evaluate(
        &db,
        &config,
        &arguments.config,
        &arguments.username,
        &arguments.fingerprint,
        &arguments.key_type,
        &arguments.key_base64,
    )
    .map_err(|_| ())?;
    Ok(decision.authorized_keys_line().map(str::to_owned))
}
