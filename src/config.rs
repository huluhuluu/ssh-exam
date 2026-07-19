use std::{fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub database_path: PathBuf,
    pub quiz_path: PathBuf,
    #[serde(default)]
    pub quiz_directory: Option<PathBuf>,
    pub tui_path: PathBuf,
    #[serde(default = "default_tui_run_as")]
    pub tui_run_as: String,
    #[serde(default = "default_sudo_path")]
    pub sudo_path: PathBuf,
    #[serde(default = "default_tui_language")]
    pub tui_language: String,
    #[doc(hidden)]
    #[serde(default, rename = "proxy_refuse_command", skip_serializing)]
    pub legacy_proxy_refuse_command: Option<PathBuf>,
    #[serde(default = "default_admin_bind")]
    pub admin_bind: SocketAddr,
    pub admin_auth_path: PathBuf,
    #[serde(default = "default_busy_timeout_ms")]
    pub busy_timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAuthConfig {
    pub password_hash: String,
    pub session_secret_base64: String,
    #[serde(default = "default_session_ttl_seconds")]
    pub session_ttl_seconds: u64,
}

fn default_sudo_path() -> PathBuf {
    PathBuf::from("/usr/bin/sudo")
}

fn default_tui_language() -> String {
    "bilingual".to_owned()
}

fn default_tui_run_as() -> String {
    "ssh-exam-tui".to_owned()
}

fn default_admin_bind() -> SocketAddr {
    "127.0.0.1:8787".parse().expect("static loopback address")
}

fn default_busy_timeout_ms() -> u64 {
    5_000
}

fn default_session_ttl_seconds() -> u64 {
    8 * 60 * 60
}

impl AppConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = fs::read(path)
            .with_context(|| format!("failed to read application config {}", path.display()))?;
        let config: Self = serde_json::from_slice(&raw)
            .with_context(|| format!("invalid application config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        for (label, path) in [
            ("database_path", &self.database_path),
            ("quiz_path", &self.quiz_path),
            ("tui_path", &self.tui_path),
            ("sudo_path", &self.sudo_path),
            ("admin_auth_path", &self.admin_auth_path),
        ] {
            if !path.is_absolute() {
                bail!("{label} must be an absolute path");
            }
        }
        if let Some(path) = &self.quiz_directory {
            if !path.is_absolute() {
                bail!("quiz_directory must be an absolute path");
            }
        }
        if !self.admin_bind.ip().is_loopback() {
            bail!("admin_bind must be a loopback address");
        }
        validate_service_username(&self.tui_run_as)?;
        if !matches!(self.tui_language.as_str(), "en" | "zh" | "bilingual") {
            bail!("tui_language must be en, zh, or bilingual");
        }
        if !(10..=60_000).contains(&self.busy_timeout_ms) {
            bail!("busy_timeout_ms must be between 10 and 60000");
        }
        Ok(())
    }

    pub fn busy_timeout(&self) -> Duration {
        Duration::from_millis(self.busy_timeout_ms)
    }
}

fn validate_service_username(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        bail!("tui_run_as must be a valid Unix username");
    };
    if value.len() > 32
        || !(first.is_ascii_lowercase() || first == b'_')
        || !bytes
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
    {
        bail!("tui_run_as must be a valid Unix username");
    }
    Ok(())
}

impl AdminAuthConfig {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = fs::read(path)
            .with_context(|| format!("failed to read admin auth config {}", path.display()))?;
        let config: Self = serde_json::from_slice(&raw)
            .with_context(|| format!("invalid admin auth config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let password_hash = argon2::PasswordHash::new(&self.password_hash)
            .map_err(|error| anyhow::anyhow!("password_hash is not a PHC string: {error}"))?;
        if !password_hash.algorithm.as_str().starts_with("argon2") {
            bail!("password_hash must use Argon2");
        }
        let secret = STANDARD
            .decode(&self.session_secret_base64)
            .context("session_secret_base64 is not valid base64")?;
        if secret.len() < 32 {
            bail!("session secret must contain at least 32 bytes");
        }
        if !(300..=7 * 24 * 60 * 60).contains(&self.session_ttl_seconds) {
            bail!("session_ttl_seconds must be between 300 and 604800");
        }
        Ok(())
    }

    pub fn session_secret(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(&self.session_secret_base64)
            .context("session_secret_base64 is not valid base64")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_public_admin_bind() {
        let config = AppConfig {
            database_path: "/var/lib/ssh-exam/test.db".into(),
            quiz_path: "/var/lib/ssh-exam/test-quiz.json".into(),
            quiz_directory: None,
            tui_path: "/usr/bin/tui".into(),
            tui_run_as: "ssh-exam-tui".to_owned(),
            sudo_path: "/usr/bin/sudo".into(),
            tui_language: "bilingual".to_owned(),
            legacy_proxy_refuse_command: None,
            admin_bind: "0.0.0.0:8787".parse().unwrap(),
            admin_auth_path: "/etc/ssh-exam/test-auth.json".into(),
            busy_timeout_ms: 5_000,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn accepts_but_does_not_serialize_legacy_proxy_refuse_command() {
        let raw = br#"{
            "database_path": "/var/lib/ssh-exam/test.db",
            "quiz_path": "/var/lib/ssh-exam/quiz.json",
            "tui_path": "/usr/bin/ssh-exam-tui",
            "tui_run_as": "ssh-exam-tui",
            "sudo_path": "/usr/bin/sudo",
            "tui_language": "bilingual",
            "proxy_refuse_command": "/usr/sbin/nologin",
            "admin_bind": "127.0.0.1:8787",
            "admin_auth_path": "/etc/ssh-exam/admin-auth.json",
            "busy_timeout_ms": 5000
        }"#;
        let config: AppConfig = serde_json::from_slice(raw).unwrap();
        assert_eq!(
            config.legacy_proxy_refuse_command,
            Some(PathBuf::from("/usr/sbin/nologin"))
        );
        assert!(!serde_json::to_string(&config)
            .unwrap()
            .contains("proxy_refuse_command"));
    }
}
