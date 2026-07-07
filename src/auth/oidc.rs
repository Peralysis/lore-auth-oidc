use std::str::FromStr;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest,
};
use serde_json::{Map, Value};

use crate::store::UserIdentity;

#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    pub url: String,
    pub csrf_state: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn authorization_url(&self) -> Result<AuthorizationRequest>;
    async fn exchange_code(
        &self,
        code: &str,
        nonce: &str,
        pkce_verifier: &str,
    ) -> Result<UserIdentity>;
}

#[derive(Clone, Copy, Debug)]
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
}

impl ClientAuthMethod {
    fn auth_type(self) -> AuthType {
        match self {
            Self::ClientSecretBasic => AuthType::BasicAuth,
            Self::ClientSecretPost => AuthType::RequestBody,
        }
    }
}

impl FromStr for ClientAuthMethod {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            _ => bail!("OIDC_CLIENT_AUTH_METHOD must be client_secret_basic or client_secret_post"),
        }
    }
}

#[derive(Clone)]
pub struct OidcProvider {
    issuer_url: String,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    scopes: Vec<String>,
    display_name_claim: Option<String>,
    username_claim: Option<String>,
    client_auth_method: ClientAuthMethod,
    http_client: reqwest::Client,
}

impl OidcProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_url: String,
        client_id: String,
        client_secret: String,
        redirect_url: String,
        scopes: Vec<String>,
        display_name_claim: Option<String>,
        username_claim: Option<String>,
        client_auth_method: ClientAuthMethod,
    ) -> Result<Self> {
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to construct OIDC HTTP client")?;
        Ok(Self {
            issuer_url,
            client_id,
            client_secret,
            redirect_url,
            scopes,
            display_name_claim,
            username_claim,
            client_auth_method,
            http_client,
        })
    }

    async fn metadata(&self) -> Result<CoreProviderMetadata> {
        let issuer = IssuerUrl::new(self.issuer_url.clone())?;
        CoreProviderMetadata::discover_async(issuer, &self.http_client)
            .await
            .context("OIDC discovery failed")
    }
}

#[async_trait]
impl IdentityProvider for OidcProvider {
    async fn authorization_url(&self) -> Result<AuthorizationRequest> {
        let client = CoreClient::from_provider_metadata(
            self.metadata().await?,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_auth_type(self.client_auth_method.auth_type())
        .set_redirect_uri(RedirectUrl::new(self.redirect_url.clone())?);

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge);
        for scope in &self.scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let (url, csrf, nonce) = request.url();

        Ok(AuthorizationRequest {
            url: url.to_string(),
            csrf_state: csrf.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        nonce: &str,
        pkce_verifier: &str,
    ) -> Result<UserIdentity> {
        let client = CoreClient::from_provider_metadata(
            self.metadata().await?,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_auth_type(self.client_auth_method.auth_type())
        .set_redirect_uri(RedirectUrl::new(self.redirect_url.clone())?);

        let response = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_owned()))
            .request_async(&self.http_client)
            .await
            .context("OIDC token exchange failed")?;
        let id_token = response
            .id_token()
            .context("OIDC provider returned no ID token")?;
        let claims = id_token
            .claims(&client.id_token_verifier(), &Nonce::new(nonce.to_owned()))
            .context("OIDC ID token validation failed")?;

        // The library above has validated this exact compact token. Decode its payload only to
        // support provider-specific claims that are not part of StandardClaims.
        let raw_claims = decode_claims(&id_token.to_string())?;
        let user_id = claims.subject().to_string();
        let preferred_username = resolve_claim(
            &raw_claims,
            self.username_claim.as_deref(),
            &["preferred_username", "email", "name"],
            &user_id,
        )?;
        let display_name = resolve_claim(
            &raw_claims,
            self.display_name_claim.as_deref(),
            &["name", "preferred_username", "email"],
            &user_id,
        )?;

        Ok(UserIdentity {
            user_id,
            display_name,
            preferred_username,
        })
    }
}

fn decode_claims(id_token: &str) -> Result<Map<String, Value>> {
    let payload = id_token
        .split('.')
        .nth(1)
        .context("OIDC ID token is malformed")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .context("OIDC ID token payload is not base64url")?;
    let value: Value =
        serde_json::from_slice(&bytes).context("OIDC ID token payload is not JSON")?;
    value
        .as_object()
        .cloned()
        .context("OIDC ID token claims must be a JSON object")
}

fn resolve_claim(
    claims: &Map<String, Value>,
    configured: Option<&str>,
    fallbacks: &[&str],
    final_fallback: &str,
) -> Result<String> {
    if let Some(name) = configured {
        return claim_string(claims, name).with_context(|| {
            format!("configured OIDC identity claim `{name}` is missing or not a non-empty string")
        });
    }
    Ok(fallbacks
        .iter()
        .find_map(|name| claim_string(claims, name).ok())
        .unwrap_or_else(|| final_fallback.to_owned()))
}

fn claim_string(claims: &Map<String, Value>, name: &str) -> Result<String> {
    let value = claims
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if value.is_empty() {
        bail!("claim has no string value");
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn claims(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn resolves_standard_claims_in_order() {
        let values =
            claims(json!({"name": "Ada", "preferred_username": "ada", "email": "a@example.com"}));
        assert_eq!(
            resolve_claim(&values, None, &["preferred_username", "email"], "sub").unwrap(),
            "ada"
        );
    }

    #[test]
    fn resolves_arbitrary_configured_claim() {
        let values = claims(json!({"cognito:username": "ada-cognito", "name": "Ada"}));
        assert_eq!(
            resolve_claim(&values, Some("cognito:username"), &["name"], "sub").unwrap(),
            "ada-cognito"
        );
    }

    #[test]
    fn rejects_invalid_configured_claim() {
        let values = claims(json!({"groups": ["developers"], "empty": " "}));
        assert!(resolve_claim(&values, Some("missing"), &["name"], "sub").is_err());
        assert!(resolve_claim(&values, Some("groups"), &["name"], "sub").is_err());
        assert!(resolve_claim(&values, Some("empty"), &["name"], "sub").is_err());
    }

    #[test]
    fn falls_back_to_subject() {
        assert_eq!(
            resolve_claim(&Map::new(), None, &["name", "email"], "subject").unwrap(),
            "subject"
        );
    }

    #[test]
    fn parses_supported_client_auth_methods() {
        assert!(matches!(
            "client_secret_basic".parse().unwrap(),
            ClientAuthMethod::ClientSecretBasic
        ));
        assert!(matches!(
            "client_secret_post".parse().unwrap(),
            ClientAuthMethod::ClientSecretPost
        ));
        assert!("private_key_jwt".parse::<ClientAuthMethod>().is_err());
    }
}
