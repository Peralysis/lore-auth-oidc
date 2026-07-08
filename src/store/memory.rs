use std::{collections::HashMap, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use rand::{Rng, distr::Alphanumeric};
use tokio::sync::RwLock;

use super::{
    AuthSession, CompletedSession, OidcAttempt, SessionState, SessionStore, StoreError,
    UserIdentity,
};

/// Upper bound on concurrently stored login sessions. StartAuthSession is
/// unauthenticated, so the store must not grow without limit.
const MAX_SESSIONS: usize = 10_000;

#[derive(Default)]
struct Sessions {
    by_code: HashMap<String, AuthSession>,
    code_by_oidc_state: HashMap<String, String>,
}

impl Sessions {
    fn purge_expired(&mut self) {
        let now = SystemTime::now();
        self.by_code.retain(|_, session| now < session.expires_at);
        self.code_by_oidc_state
            .retain(|_, code| self.by_code.contains_key(code));
    }
}

#[derive(Clone)]
pub struct MemoryStore {
    sessions: Arc<RwLock<Sessions>>,
    users: Arc<RwLock<HashMap<String, UserIdentity>>>,
    ttl: std::time::Duration,
}

impl MemoryStore {
    pub fn new(ttl: std::time::Duration) -> Self {
        Self {
            sessions: Default::default(),
            users: Default::default(),
            ttl,
        }
    }

    fn random_code() -> String {
        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect()
    }

    fn ensure_fresh(session: &AuthSession) -> Result<(), StoreError> {
        if SystemTime::now() >= session.expires_at {
            Err(StoreError::Expired)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn create_session(&self, client_state: String) -> Result<AuthSession, StoreError> {
        let session = AuthSession {
            code: Self::random_code(),
            client_state,
            expires_at: SystemTime::now() + self.ttl,
            state: SessionState::Pending { oidc: None },
        };
        let mut sessions = self.sessions.write().await;
        sessions.purge_expired();
        if sessions.by_code.len() >= MAX_SESSIONS {
            return Err(StoreError::CapacityExceeded);
        }
        sessions
            .by_code
            .insert(session.code.clone(), session.clone());
        Ok(session)
    }

    async fn get_session(&self, code: &str) -> Result<AuthSession, StoreError> {
        let session = self
            .sessions
            .read()
            .await
            .by_code
            .get(code)
            .cloned()
            .ok_or(StoreError::NotFound)?;
        Self::ensure_fresh(&session)?;
        Ok(session)
    }

    async fn begin_oidc(&self, code: &str, attempt: OidcAttempt) -> Result<(), StoreError> {
        let mut sessions = self.sessions.write().await;
        let new_state = attempt.csrf_state.clone();
        let session = sessions.by_code.get_mut(code).ok_or(StoreError::NotFound)?;
        Self::ensure_fresh(session)?;
        let previous_state = match &mut session.state {
            SessionState::Pending { oidc } => oidc.replace(attempt).map(|old| old.csrf_state),
            SessionState::Completed(_) => return Err(StoreError::NotPending),
        };
        if let Some(previous_state) = previous_state {
            sessions.code_by_oidc_state.remove(&previous_state);
        }
        sessions.code_by_oidc_state.insert(new_state, code.into());
        Ok(())
    }

    async fn session_for_oidc_state(&self, state: &str) -> Result<AuthSession, StoreError> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .code_by_oidc_state
            .get(state)
            .and_then(|code| sessions.by_code.get(code))
            .filter(|session| {
                matches!(
                    &session.state,
                    SessionState::Pending { oidc: Some(attempt) }
                        if attempt.csrf_state == state
                )
            })
            .cloned()
            .ok_or(StoreError::InvalidOidcState)?;
        Self::ensure_fresh(&session)?;
        Ok(session)
    }

    async fn complete_session(
        &self,
        code: &str,
        user: UserIdentity,
        token: String,
        token_expires_at: i64,
    ) -> Result<(), StoreError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.by_code.get_mut(code).ok_or(StoreError::NotFound)?;
        Self::ensure_fresh(session)?;
        let oidc_state = match &session.state {
            SessionState::Pending { oidc } => {
                oidc.as_ref().map(|attempt| attempt.csrf_state.clone())
            }
            SessionState::Completed(_) => return Err(StoreError::NotPending),
        };
        session.state = SessionState::Completed(CompletedSession {
            user: user.clone(),
            token,
            token_expires_at,
        });
        if let Some(oidc_state) = oidc_state {
            sessions.code_by_oidc_state.remove(&oidc_state);
        }
        drop(sessions);
        self.users.write().await.insert(user.user_id.clone(), user);
        Ok(())
    }

    async fn users_by_id(&self, ids: &[String]) -> Vec<UserIdentity> {
        let users = self.users.read().await;
        ids.iter().filter_map(|id| users.get(id).cloned()).collect()
    }

    async fn user_by_display_name(&self, display_name: &str) -> Option<UserIdentity> {
        self.users
            .read()
            .await
            .values()
            .find(|user| user.display_name == display_name)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn user() -> UserIdentity {
        UserIdentity {
            user_id: "user-1".into(),
            display_name: "Ada Lovelace".into(),
            preferred_username: "ada".into(),
        }
    }

    fn attempt(state: &str) -> OidcAttempt {
        OidcAttempt {
            csrf_state: state.into(),
            nonce: "nonce".into(),
            pkce_verifier: "verifier".into(),
        }
    }

    #[tokio::test]
    async fn session_creation_and_expiration() {
        let store = MemoryStore::new(Duration::from_millis(20));
        let session = store.create_session("client-state".into()).await.unwrap();
        assert_eq!(
            store.get_session(&session.code).await.unwrap().client_state,
            "client-state"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(matches!(
            store.get_session(&session.code).await,
            Err(StoreError::Expired)
        ));
    }

    #[tokio::test]
    async fn creating_a_session_purges_expired_sessions() {
        let store = MemoryStore::new(Duration::from_millis(20));
        let expired = store.create_session("state".into()).await.unwrap();
        store
            .begin_oidc(&expired.code, attempt("oidc-state"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        store.create_session("state".into()).await.unwrap();
        let sessions = store.sessions.read().await;
        assert!(!sessions.by_code.contains_key(&expired.code));
        assert!(sessions.code_by_oidc_state.is_empty());
        assert_eq!(sessions.by_code.len(), 1);
    }

    #[tokio::test]
    async fn enforces_session_capacity() {
        let store = MemoryStore::new(Duration::from_secs(30));
        {
            let mut sessions = store.sessions.write().await;
            for index in 0..MAX_SESSIONS {
                let code = format!("code-{index}");
                sessions.by_code.insert(
                    code.clone(),
                    AuthSession {
                        code,
                        client_state: "state".into(),
                        expires_at: SystemTime::now() + Duration::from_secs(30),
                        state: SessionState::Pending { oidc: None },
                    },
                );
            }
        }
        assert!(matches!(
            store.create_session("state".into()).await,
            Err(StoreError::CapacityExceeded)
        ));
    }

    #[tokio::test]
    async fn finds_sessions_by_oidc_state_until_completed() {
        let store = MemoryStore::new(Duration::from_secs(30));
        let session = store.create_session("state".into()).await.unwrap();
        store
            .begin_oidc(&session.code, attempt("first-state"))
            .await
            .unwrap();
        store
            .begin_oidc(&session.code, attempt("second-state"))
            .await
            .unwrap();
        assert!(matches!(
            store.session_for_oidc_state("first-state").await,
            Err(StoreError::InvalidOidcState)
        ));
        assert_eq!(
            store
                .session_for_oidc_state("second-state")
                .await
                .unwrap()
                .code,
            session.code
        );
        store
            .complete_session(&session.code, user(), "jwt".into(), 1234)
            .await
            .unwrap();
        assert!(matches!(
            store.session_for_oidc_state("second-state").await,
            Err(StoreError::InvalidOidcState)
        ));
    }

    #[tokio::test]
    async fn session_completion_indexes_user() {
        let store = MemoryStore::new(Duration::from_secs(30));
        let session = store.create_session("state".into()).await.unwrap();
        store
            .complete_session(&session.code, user(), "jwt".into(), 1234)
            .await
            .unwrap();
        let completed = store.get_session(&session.code).await.unwrap();
        assert!(matches!(completed.state, SessionState::Completed(_)));
        assert_eq!(
            store.user_by_display_name("Ada Lovelace").await,
            Some(user())
        );
        assert_eq!(
            store
                .complete_session(&session.code, user(), "again".into(), 1234)
                .await,
            Err(StoreError::NotPending)
        );
    }
}
