use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    pub key_type: String,
    pub key_base64: String,
    pub comment: Option<String>,
    pub fingerprint: String,
}

impl PublicKey {
    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim();
        let mut fields = line.splitn(3, char::is_whitespace);
        let key_type = fields.next().unwrap_or_default();
        let key_base64 = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("public key must contain a type and base64 blob"))?;
        let comment = fields.next().map(str::trim).filter(|s| !s.is_empty());

        validate_key_type(key_type)?;
        let fingerprint = fingerprint(key_base64)?;
        Ok(Self {
            key_type: key_type.to_owned(),
            key_base64: key_base64.to_owned(),
            comment: comment.map(str::to_owned),
            fingerprint,
        })
    }

    pub fn authorized_key(&self) -> String {
        format!("{} {} ssh-exam-gate", self.key_type, self.key_base64)
    }
}

pub fn validate_key_type(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'@' | b'.' | b'_'))
    {
        bail!("invalid public key type");
    }
    Ok(())
}

pub fn fingerprint(key_base64: &str) -> Result<String> {
    if key_base64.is_empty() || key_base64.bytes().any(|byte| byte.is_ascii_whitespace()) {
        bail!("invalid public key base64 blob");
    }
    let decoded = general_purpose::STANDARD
        .decode(key_base64)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(key_base64))
        .context("invalid public key base64 blob")?;
    if decoded.is_empty() {
        bail!("public key blob is empty");
    }
    let digest = Sha256::digest(decoded);
    Ok(format!(
        "SHA256:{}",
        general_purpose::STANDARD_NO_PAD.encode(digest)
    ))
}

pub fn validate_fingerprint(value: &str) -> Result<()> {
    let encoded = value
        .strip_prefix("SHA256:")
        .ok_or_else(|| anyhow::anyhow!("fingerprint must use SHA256 format"))?;
    let decoded = general_purpose::STANDARD_NO_PAD
        .decode(encoded)
        .context("invalid SHA256 fingerprint")?;
    if decoded.len() != 32 {
        bail!("invalid SHA256 fingerprint length");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1YQ2hhbmdlVGhpc0lzVGVzdEtleURhdGE test-device";

    #[test]
    fn parses_comment_as_metadata_and_fingerprints_blob() {
        let key = PublicKey::parse(KEY).unwrap();
        assert_eq!(key.key_type, "ssh-ed25519");
        assert_eq!(key.comment.as_deref(), Some("test-device"));
        assert_eq!(
            key.fingerprint,
            fingerprint("AAAAC3NzaC1lZDI1NTE5AAAAIE1YQ2hhbmdlVGhpc0lzVGVzdEtleURhdGE").unwrap()
        );
        validate_fingerprint(&key.fingerprint).unwrap();
    }

    #[test]
    fn rejects_options_and_invalid_base64() {
        assert!(PublicKey::parse("command=x ssh-ed25519 AAAA").is_err());
        assert!(PublicKey::parse("ssh-ed25519 not-base64!").is_err());
    }

    #[test]
    fn known_sha256_fingerprint() {
        assert_eq!(
            fingerprint("aGVsbG8=").unwrap(),
            "SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
        );
    }
}
