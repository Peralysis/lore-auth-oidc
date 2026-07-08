mod memory;

use std::time::SystemTime;

use async_trait::async_trait;
use thiserror::Error;

pub use memory::MemoryStore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserIdentity {
    pub user_id: String,
    pub display_name: String,
    pub preferred_username: String,
}

#[derive(Clone, Debug)]
pub struct OidcAttempt {
    pub csrf_state: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

#[derive(Clone, Debug)]
pub struct CompletedSession {
    pub user: UserIdentity,
    pub token: String,
    pub token_expires_at: i64,
}

#[derive(Clone, Debug)]
pub enum SessionState {
    Pending { oidc: Option<OidcAttempt> },
    Completed(CompletedSession),
}

#[derive(Clone, Debug)]
pub struct AuthSession {
    pub code: String,
    pub client_state: String,
    pub expires_at: SystemTime,
    pub state: SessionState,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("session not found")]
    NotFound,
    #[error("session expired")]
    Expired,
    #[error("session is not pending")]
    NotPending,
    #[error("OIDC login has not started")]
    OidcNotStarted,
    #[error("OIDC state does not match")]
    InvalidOidcState,
    #[error("too many pending login sessions")]
    CapacityExceeded,
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(&self, client_state: String) -> Result<AuthSession, StoreError>;
    async fn get_session(&self, code: &str) -> Result<AuthSession, StoreError>;
    async fn begin_oidc(&self, code: &str, attempt: OidcAttempt) -> Result<(), StoreError>;
    async fn session_for_oidc_state(&self, state: &str) -> Result<AuthSession, StoreError>;
    async fn complete_session(
        &self,
        code: &str,
        user: UserIdentity,
        token: String,
        token_expires_at: i64,
    ) -> Result<(), StoreError>;
    async fn users_by_id(&self, ids: &[String]) -> Vec<UserIdentity>;
    async fn user_by_display_name(&self, display_name: &str) -> Option<UserIdentity>;
}
