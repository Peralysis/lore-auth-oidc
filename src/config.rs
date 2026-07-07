use std::{env, fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use url::Url;

use crate::auth::oidc::ClientAuthMethod;

#[derive(Clone)]
pub struct Config {
    pub adapter_public_url: Url,
    pub grpc_bind_addr: SocketAddr,
    pub http_bind_addr: SocketAddr,
    pub oidc_issuer_url: Url,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_redirect_url: Url,
    pub oidc_scopes: Vec<String>,
    pub oidc_display_name_claim: Option<String>,
    pub oidc_username_claim: Option<String>,
    pub oidc_provider_name: String,
    pub oidc_client_auth_method: ClientAuthMethod,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwt_private_key_path: PathBuf,
    pub jwt_key_id: String,
    pub session_ttl: Duration,
    pub allow_all_users: bool,
    pub lore_env: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let get = |key: &str| env::var(key).with_context(|| format!("missing {key}"));
        let adapter_public_url = get("ADAPTER_PUBLIC_URL")?.parse()?;
        let grpc_bind_addr = get("GRPC_BIND_ADDR")?.parse()?;
        let http_bind_addr = get("HTTP_BIND_ADDR")?.parse()?;
        let oidc_issuer_url: Url = get("OIDC_ISSUER_URL")?.parse()?;
        let oidc_client_id = get("OIDC_CLIENT_ID")?;
        let oidc_client_secret = read_secret("OIDC_CLIENT_SECRET")?;
        let oidc_redirect_url = get("OIDC_REDIRECT_URL")?.parse()?;
        let oidc_scopes = parse_scopes(
            env::var("OIDC_SCOPES")
                .as_deref()
                .unwrap_or("openid profile email"),
        )?;
        let oidc_display_name_claim = optional_env("OIDC_DISPLAY_NAME_CLAIM");
        let oidc_username_claim = optional_env("OIDC_USERNAME_CLAIM");
        let oidc_provider_name =
            optional_env("OIDC_PROVIDER_NAME").unwrap_or_else(|| oidc_issuer_url.to_string());
        let oidc_client_auth_method = env::var("OIDC_CLIENT_AUTH_METHOD")
            .as_deref()
            .unwrap_or("client_secret_basic")
            .parse()?;
        let jwt_issuer = get("JWT_ISSUER")?;
        let jwt_audience = get("JWT_AUDIENCE")?;
        let jwt_private_key_path = get("JWT_PRIVATE_KEY_PATH")?.into();
        let jwt_key_id = get("JWT_KEY_ID")?;
        let session_ttl = Duration::from_secs(get("SESSION_TTL_SECONDS")?.parse()?);
        let allow_all_users = get("ALLOW_ALL_USERS")?
            .parse()
            .context("ALLOW_ALL_USERS must be true or false")?;
        let lore_env = get("LORE_ENV")?;

        if session_ttl.is_zero() {
            bail!("SESSION_TTL_SECONDS must be greater than zero");
        }

        Ok(Self {
            adapter_public_url,
            grpc_bind_addr,
            http_bind_addr,
            oidc_issuer_url,
            oidc_client_id,
            oidc_client_secret,
            oidc_redirect_url,
            oidc_scopes,
            oidc_display_name_claim,
            oidc_username_claim,
            oidc_provider_name,
            oidc_client_auth_method,
            jwt_issuer,
            jwt_audience,
            jwt_private_key_path,
            jwt_key_id,
            session_ttl,
            allow_all_users,
            lore_env,
        })
    }
}

fn optional_env(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn read_secret(key: &str) -> Result<String> {
    let file_key = format!("{key}_FILE");
    if let Some(path) = optional_env(&file_key) {
        return read_secret_file(&path, &file_key);
    }
    env::var(key).with_context(|| format!("missing {key} or {file_key}"))
}

fn read_secret_file(path: &str, description: &str) -> Result<String> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("failed to read {description} at {path}"))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("{description} points to an empty secret");
    }
    Ok(value)
}

fn parse_scopes(value: &str) -> Result<Vec<String>> {
    let scopes: Vec<_> = value
        .split(|character: char| character.is_whitespace() || character == ',')
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect();
    if !scopes.iter().any(|scope| scope == "openid") {
        bail!("OIDC_SCOPES must include openid");
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn parses_space_or_comma_separated_scopes() {
        assert_eq!(
            parse_scopes("openid profile,email").unwrap(),
            ["openid", "profile", "email"]
        );
        assert!(parse_scopes("profile email").is_err());
    }

    #[test]
    fn reads_and_trims_file_secret() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "super-secret").unwrap();
        assert_eq!(
            read_secret_file(file.path().to_str().unwrap(), "TEST_SECRET_FILE").unwrap(),
            "super-secret"
        );
    }

    #[test]
    fn rejects_empty_file_secret() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(read_secret_file(file.path().to_str().unwrap(), "TEST_SECRET_FILE").is_err());
    }
}
