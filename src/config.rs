use std::{env, fs, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use url::Url;

use crate::auth::oidc::ClientAuthMethod;

#[derive(Clone)]
pub struct Config {
    pub adapter_public_url: Url,
    pub grpc_bind_addr: SocketAddr,
    pub http_bind_addr: SocketAddr,
    /// Kept as the exact configured string: OIDC issuer comparison is an
    /// exact string match, and `Url` normalization would append a trailing
    /// slash to domain-root issuers.
    pub oidc_issuer_url: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_redirect_url: String,
    pub oidc_scopes: Vec<String>,
    pub oidc_display_name_claim: Option<String>,
    pub oidc_username_claim: Option<String>,
    pub oidc_provider_name: String,
    pub oidc_client_auth_method: ClientAuthMethod,
    pub oidc_tls_root_ca: Option<Vec<u8>>,
    pub jwt_issuer: String,
    pub jwt_audience: Vec<String>,
    pub jwt_private_key_path: PathBuf,
    pub jwt_key_id: Option<String>,
    pub session_ttl: Duration,
    pub allow_all_users: bool,
    pub lore_env: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let get = |key: &str| env::var(key).with_context(|| format!("missing {key}"));
        let adapter_public_url: Url = get("ADAPTER_PUBLIC_URL")?.parse()?;
        if adapter_public_url.scheme() != "https" {
            tracing::warn!(
                url = %adapter_public_url,
                "ADAPTER_PUBLIC_URL is not HTTPS; use this only for local development"
            );
        }
        let public_origin = adapter_public_url.as_str().trim_end_matches('/').to_owned();
        let grpc_bind_addr = optional_env("GRPC_BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:50051".into())
            .parse()
            .context("GRPC_BIND_ADDR must be a socket address")?;
        let http_bind_addr = optional_env("HTTP_BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()
            .context("HTTP_BIND_ADDR must be a socket address")?;
        let oidc_issuer_url = get("OIDC_ISSUER_URL")?;
        oidc_issuer_url
            .parse::<Url>()
            .context("OIDC_ISSUER_URL must be a URL")?;
        let oidc_client_id = get("OIDC_CLIENT_ID")?;
        let oidc_client_secret = read_secret("OIDC_CLIENT_SECRET")?;
        let oidc_redirect_url = optional_env("OIDC_REDIRECT_URL")
            .unwrap_or_else(|| format!("{public_origin}/callback"));
        oidc_redirect_url
            .parse::<Url>()
            .context("OIDC_REDIRECT_URL must be a URL")?;
        let oidc_scopes = parse_scopes(
            env::var("OIDC_SCOPES")
                .as_deref()
                .unwrap_or("openid profile email"),
        )?;
        let oidc_display_name_claim = optional_env("OIDC_DISPLAY_NAME_CLAIM");
        let oidc_username_claim = optional_env("OIDC_USERNAME_CLAIM");
        let oidc_provider_name =
            optional_env("OIDC_PROVIDER_NAME").unwrap_or_else(|| oidc_issuer_url.clone());
        let oidc_client_auth_method = env::var("OIDC_CLIENT_AUTH_METHOD")
            .as_deref()
            .unwrap_or("client_secret_basic")
            .parse()?;
        let oidc_tls_root_ca = optional_env("OIDC_TLS_ROOT_CA_FILE")
            .map(|path| {
                fs::read(&path)
                    .with_context(|| format!("failed to read OIDC_TLS_ROOT_CA_FILE at {path}"))
            })
            .transpose()?;
        let jwt_issuer = optional_env("JWT_ISSUER").unwrap_or_else(|| public_origin.clone());
        let jwt_audience = parse_audiences(&get("JWT_AUDIENCE")?)?;
        let jwt_private_key_path = get("JWT_PRIVATE_KEY_PATH")?.into();
        let jwt_key_id = optional_env("JWT_KEY_ID");
        let session_ttl = Duration::from_secs(
            optional_env("SESSION_TTL_SECONDS")
                .unwrap_or_else(|| "600".into())
                .parse()
                .context("SESSION_TTL_SECONDS must be a number of seconds")?,
        );
        let allow_all_users = optional_env("ALLOW_ALL_USERS")
            .unwrap_or_else(|| "false".into())
            .parse()
            .context("ALLOW_ALL_USERS must be true or false")?;
        let lore_env = optional_env("LORE_ENV").unwrap_or_else(|| "production".into());

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
            oidc_tls_root_ca,
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

/// A Lore server may be reachable under more than one hostname alias
/// (e.g. `localhost` and `127.0.0.1` for the same local deployment), and
/// Lore clients check that a token's `aud` covers whichever one they
/// actually connected through. Comma/whitespace-separated, same shape as
/// `OIDC_SCOPES`.
fn parse_audiences(value: &str) -> Result<Vec<String>> {
    let audiences: Vec<_> = value
        .split(|character: char| character.is_whitespace() || character == ',')
        .filter(|audience| !audience.is_empty())
        .map(str::to_owned)
        .collect();
    if audiences.is_empty() {
        bail!("JWT_AUDIENCE must specify at least one audience");
    }
    Ok(audiences)
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
    fn parses_space_or_comma_separated_audiences() {
        assert_eq!(
            parse_audiences("localhost,127.0.0.1").unwrap(),
            ["localhost", "127.0.0.1"]
        );
        assert_eq!(
            parse_audiences("localhost 127.0.0.1").unwrap(),
            ["localhost", "127.0.0.1"]
        );
        assert_eq!(parse_audiences("lore.example.com").unwrap(), ["lore.example.com"]);
        assert!(parse_audiences("").is_err());
        assert!(parse_audiences("   ").is_err());
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
