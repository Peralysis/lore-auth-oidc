use std::{fs, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rsa::{
    RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};

use crate::store::UserIdentity;

const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

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
    pub aud: String,
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
    pub aud: String,
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
    audience: String,
    environment: String,
    identity_provider: String,
    modulus: String,
    exponent: String,
}

impl JwtService {
    pub fn from_path(
        path: &Path,
        key_id: String,
        issuer: String,
        audience: String,
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
        key_id: String,
        issuer: String,
        audience: String,
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

    pub fn issue_authn(&self, user: &UserIdentity) -> Result<(String, i64)> {
        let now = Utc::now().timestamp();
        let exp = now + TOKEN_TTL.as_secs() as i64;
        let claims = AuthnClaims {
            iss: self.issuer.clone(),
            sub: user.user_id.clone(),
            iat: now,
            exp,
            aud: self.audience.clone(),
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
        validation.set_audience(&[&self.audience]);
        validation
    }

    pub fn validate_authn(&self, token: &str) -> Result<AuthnClaims> {
        Ok(decode::<AuthnClaims>(token, &self.decoding_key, &self.validation())?.claims)
    }

    pub fn validate_authz(&self, token: &str) -> Result<AuthzClaims> {
        Ok(decode::<AuthzClaims>(token, &self.decoding_key, &self.validation())?.claims)
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
    Ok(vec![ResourceClaim {
        resource_id: "urc-*".into(),
        permission: vec!["read".into(), "write".into(), "admin".into()],
    }])
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

    fn service() -> JwtService {
        let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(Default::default()).unwrap();
        JwtService::from_pem(
            pem.as_bytes(),
            "test-key".into(),
            "https://auth.example.com".into(),
            "lore.example.com".into(),
            "test".into(),
            "test-oidc".into(),
        )
        .unwrap()
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
        assert!(authorizes_resource(&authz_claims, "urc-anything"));
        assert_eq!(jwt.jwks()["keys"][0]["kid"], "test-key");
    }

    #[test]
    fn creates_expected_resource_claims() {
        let resources = resource_claims(&["urc-abc".into(), "urc-def".into()], true).unwrap();
        assert_eq!(resources[0].resource_id, "urc-*");
        assert_eq!(resources[0].permission, ["read", "write", "admin"]);
        assert!(resource_claims(&["repository".into()], true).is_err());
        assert!(resource_claims(&["urc-abc".into()], false).is_err());
    }
}
