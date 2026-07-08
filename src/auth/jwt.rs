use std::{fs, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rsa::{
    RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::store::UserIdentity;

const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
const AUTHN_TOKEN_TYPE: &str = "lore-authn";
const AUTHZ_TOKEN_TYPE: &str = "lore-authz";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceClaim {
    pub resource_id: String,
    pub permission: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthnClaims {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub aud: Vec<String>,
    pub typ: String,
    pub env: String,
    pub name: String,
    pub preferred_username: String,
    pub is_service_account: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzClaims {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub aud: Vec<String>,
    pub typ: String,
    pub env: String,
    pub name: String,
    pub preferred_username: String,
    pub idp: String,
    pub resources: Vec<ResourceClaim>,
}

#[derive(Clone)]
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    key_id: String,
    issuer: String,
    audience: Vec<String>,
    environment: String,
    identity_provider: String,
    modulus: String,
    exponent: String,
}

impl JwtService {
    pub fn from_path(
        path: &Path,
        key_id: Option<String>,
        issuer: String,
        audience: Vec<String>,
        environment: String,
        identity_provider: String,
    ) -> Result<Self> {
        let pem = fs::read(path)
            .with_context(|| format!("failed to read JWT private key at {}", path.display()))?;
        Self::from_pem(
            &pem,
            key_id,
            issuer,
            audience,
            environment,
            identity_provider,
        )
    }

    pub fn from_pem(
        pem: &[u8],
        key_id: Option<String>,
        issuer: String,
        audience: Vec<String>,
        environment: String,
        identity_provider: String,
    ) -> Result<Self> {
        let text = std::str::from_utf8(pem).context("JWT private key is not UTF-8 PEM")?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(text)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(text))
            .context("JWT private key must be an RSA PKCS#8 or PKCS#1 PEM")?;
        let public = private_key.to_public_key();
        let modulus = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let exponent = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let key_id = key_id.unwrap_or_else(|| jwk_thumbprint(&exponent, &modulus));

        Ok(Self {
            encoding_key: EncodingKey::from_rsa_pem(pem)?,
            decoding_key: DecodingKey::from_rsa_components(&modulus, &exponent)?,
            key_id,
            issuer,
            audience,
            environment,
            identity_provider,
            modulus,
            exponent,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn issue_authn(&self, user: &UserIdentity) -> Result<(String, i64)> {
        let now = Utc::now().timestamp();
        let exp = now + TOKEN_TTL.as_secs() as i64;
        let claims = AuthnClaims {
            iss: self.issuer.clone(),
            sub: user.user_id.clone(),
            iat: now,
            exp,
            aud: self.audience.clone(),
            typ: AUTHN_TOKEN_TYPE.into(),
            env: self.environment.clone(),
            name: user.display_name.clone(),
            preferred_username: user.preferred_username.clone(),
            is_service_account: false,
        };
        Ok((self.encode(&claims)?, exp))
    }

    pub fn issue_authz(
        &self,
        authn: &AuthnClaims,
        resources: Vec<ResourceClaim>,
    ) -> Result<(String, i64)> {
        let now = Utc::now().timestamp();
        let exp = (now + TOKEN_TTL.as_secs() as i64).min(authn.exp);
        let claims = AuthzClaims {
            iss: self.issuer.clone(),
            sub: authn.sub.clone(),
            iat: now,
            exp,
            aud: self.audience.clone(),
            typ: AUTHZ_TOKEN_TYPE.into(),
            env: self.environment.clone(),
            name: authn.name.clone(),
            preferred_username: authn.preferred_username.clone(),
            idp: self.identity_provider.clone(),
            resources,
        };
        Ok((self.encode(&claims)?, exp))
    }

    fn encode<T: Serialize>(&self, claims: &T) -> Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());
        Ok(encode(&header, claims, &self.encoding_key)?)
    }

    fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.audience);
        validation
    }

    pub fn validate_authn(&self, token: &str) -> Result<AuthnClaims> {
        let claims = decode::<AuthnClaims>(token, &self.decoding_key, &self.validation())?.claims;
        if claims.typ != AUTHN_TOKEN_TYPE {
            bail!("token is not an authentication token");
        }
        Ok(claims)
    }

    pub fn validate_authz(&self, token: &str) -> Result<AuthzClaims> {
        let claims = decode::<AuthzClaims>(token, &self.decoding_key, &self.validation())?.claims;
        if claims.typ != AUTHZ_TOKEN_TYPE {
            bail!("token is not an authorization token");
        }
        Ok(claims)
    }

    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": self.key_id,
                "n": self.modulus,
                "e": self.exponent
            }]
        })
    }
}

/// RFC 7638 JWK thumbprint of an RSA public key: SHA-256 over the required
/// members in lexicographic order, without whitespace.
fn jwk_thumbprint(exponent: &str, modulus: &str) -> String {
    let canonical = format!(r#"{{"e":"{exponent}","kty":"RSA","n":"{modulus}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

pub fn resource_claims(requested: &[String], allow_all: bool) -> Result<Vec<ResourceClaim>> {
    if !allow_all {
        bail!("no authorization policy backend is configured");
    }
    if requested.is_empty() {
        bail!("at least one resource_id is required");
    }
    if requested
        .iter()
        .any(|resource| resource != "urc-*" && !resource.starts_with("urc-") || resource == "urc-")
    {
        bail!("resource IDs must use urc-{{repository_id}} or urc-*");
    }
    let mut resources: Vec<ResourceClaim> = Vec::new();
    for resource in requested {
        if resources.iter().any(|claim| &claim.resource_id == resource) {
            continue;
        }
        resources.push(ResourceClaim {
            resource_id: resource.clone(),
            permission: vec!["read".into(), "write".into(), "admin".into()],
        });
    }
    Ok(resources)
}

pub fn authorizes_resource(claims: &AuthzClaims, resource: &str) -> bool {
    claims.resources.iter().any(|claim| {
        (claim.resource_id == "urc-*" || claim.resource_id == resource)
            && !claim.permission.is_empty()
    })
}

#[cfg(test)]
mod tests {
    use rsa::{pkcs8::EncodePrivateKey, rand_core::OsRng};

    use super::*;

    fn pem() -> String {
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        key.to_pkcs8_pem(Default::default()).unwrap().to_string()
    }

    fn service_from(pem: &str, key_id: Option<String>) -> JwtService {
        JwtService::from_pem(
            pem.as_bytes(),
            key_id,
            "https://auth.example.com".into(),
            vec!["lore.example.com".into()],
            "test".into(),
            "test-oidc".into(),
        )
        .unwrap()
    }

    fn service() -> JwtService {
        service_from(&pem(), Some("test-key".into()))
    }

    fn user() -> UserIdentity {
        UserIdentity {
            user_id: "oidc-subject".into(),
            display_name: "Ada Lovelace".into(),
            preferred_username: "ada".into(),
        }
    }

    #[test]
    fn creates_and_validates_tokens_and_jwks() {
        let jwt = service();
        let (authn, _) = jwt.issue_authn(&user()).unwrap();
        let authn_claims = jwt.validate_authn(&authn).unwrap();
        assert_eq!(authn_claims.sub, "oidc-subject");
        let resources = resource_claims(&["urc-repository".into()], true).unwrap();
        let (authz, _) = jwt.issue_authz(&authn_claims, resources).unwrap();
        let authz_claims = jwt.validate_authz(&authz).unwrap();
        assert_eq!(authz_claims.idp, "test-oidc");
        assert!(authorizes_resource(&authz_claims, "urc-repository"));
        assert!(!authorizes_resource(&authz_claims, "urc-other"));
        assert_eq!(jwt.jwks()["keys"][0]["kid"], "test-key");
    }

    #[test]
    fn emits_and_validates_multiple_audiences() {
        let key = pem();
        let jwt = JwtService::from_pem(
            key.as_bytes(),
            Some("test-key".into()),
            "https://auth.example.com".into(),
            vec!["localhost".into(), "127.0.0.1".into()],
            "test".into(),
            "test-oidc".into(),
        )
        .unwrap();
        let (authn, _) = jwt.issue_authn(&user()).unwrap();

        // Decode the token's payload segment directly (no jsonwebtoken
        // involved, just base64 + serde) to confirm `aud` is a real JSON
        // array in the token, not a single opaque string.
        let payload_segment = authn.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
        let claims: AuthnClaims = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(claims.aud, vec!["localhost", "127.0.0.1"]);

        // Same signing key, but configured with only one of the two
        // audiences the token was issued for: jsonwebtoken accepts any
        // overlap between the token's aud and the validator's configured
        // set, not exact equality — this is the behavior the real Lore
        // client's own aud check relies on (a token valid for multiple
        // hostname aliases at once).
        let single_audience = JwtService::from_pem(
            key.as_bytes(),
            Some("test-key".into()),
            "https://auth.example.com".into(),
            vec!["127.0.0.1".into()],
            "test".into(),
            "test-oidc".into(),
        )
        .unwrap();
        assert!(single_audience.validate_authn(&authn).is_ok());

        // An audience absent from the token is correctly still rejected.
        let unrelated_audience = JwtService::from_pem(
            key.as_bytes(),
            Some("test-key".into()),
            "https://auth.example.com".into(),
            vec!["unrelated.example.com".into()],
            "test".into(),
            "test-oidc".into(),
        )
        .unwrap();
        assert!(unrelated_audience.validate_authn(&authn).is_err());
    }

    #[test]
    fn rejects_tokens_of_the_wrong_type() {
        let jwt = service();
        let (authn, _) = jwt.issue_authn(&user()).unwrap();
        let authn_claims = jwt.validate_authn(&authn).unwrap();
        let resources = resource_claims(&["urc-repository".into()], true).unwrap();
        let (authz, _) = jwt.issue_authz(&authn_claims, resources).unwrap();
        assert!(jwt.validate_authz(&authn).is_err());
        assert!(jwt.validate_authn(&authz).is_err());
    }

    #[test]
    fn derives_a_stable_jwk_thumbprint_key_id() {
        let key = pem();
        let first = service_from(&key, None);
        let second = service_from(&key, None);
        assert_eq!(first.key_id(), second.key_id());
        assert_eq!(first.key_id().len(), 43); // base64url SHA-256, no padding
        let other_key = pem();
        assert_ne!(service_from(&other_key, None).key_id(), first.key_id());
    }

    #[test]
    fn creates_expected_resource_claims() {
        let resources = resource_claims(
            &["urc-abc".into(), "urc-def".into(), "urc-abc".into()],
            true,
        )
        .unwrap();
        assert_eq!(
            resources
                .iter()
                .map(|claim| claim.resource_id.as_str())
                .collect::<Vec<_>>(),
            ["urc-abc", "urc-def"]
        );
        assert!(
            resources
                .iter()
                .all(|claim| claim.permission == ["read", "write", "admin"])
        );
        assert!(resource_claims(&["repository".into()], true).is_err());
        assert!(resource_claims(&["urc-".into()], true).is_err());
        assert!(resource_claims(&["urc-abc".into()], false).is_err());
        assert!(resource_claims(&[], true).is_err());
    }

    #[test]
    fn wildcard_grant_authorizes_any_resource() {
        let jwt = service();
        let (authn, _) = jwt.issue_authn(&user()).unwrap();
        let authn_claims = jwt.validate_authn(&authn).unwrap();
        let resources = resource_claims(&["urc-*".into()], true).unwrap();
        let (authz, _) = jwt.issue_authz(&authn_claims, resources).unwrap();
        let authz_claims = jwt.validate_authz(&authz).unwrap();
        assert!(authorizes_resource(&authz_claims, "urc-anything"));
    }
}
