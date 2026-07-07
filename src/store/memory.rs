use std::{collections::HashMap, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use rand::{Rng, distr::Alphanumeric};
use tokio::sync::RwLock;

use super::{
    AuthSession, CompletedSession, OidcAttempt, SessionState, SessionStore, StoreError,
    UserIdentity,
};

#[derive(Clone)]
pub struct MemoryStore {
    sessions: Arc<RwLock<HashMap<String, AuthSession>>>,
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
    async fn create_session(&self, client_state: String) -> AuthSession {
        let session = AuthSession {
            code: Self::random_code(),
            client_state,
            expires_at: SystemTime::now() + self.ttl,
            state: SessionState::Pending { oidc: None },
        };
        self.sessions
            .write()
            .await
            .insert(session.code.clone(), session.clone());
        session
    }

    async fn get_session(&self, code: &str) -> Result<AuthSession, StoreError> {
        let session = self
            .sessions
            .read()
            .await
            .get(code)
            .cloned()
            .ok_or(StoreError::NotFound)?;
        Self::ensure_fresh(&session)?;
        Ok(session)
    }

    async fn begin_oidc(&self, code: &str, attempt: OidcAttempt) -> Result<(), StoreError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(code).ok_or(StoreError::NotFound)?;
        Self::ensure_fresh(session)?;
        match &mut session.state {
            SessionState::Pending { oidc } => {
                *oidc = Some(attempt);
                Ok(())
            }
            SessionState::Completed(_) => Err(StoreError::NotPending),
        }
    }

    async fn session_for_oidc_state(&self, state: &str) -> Result<AuthSession, StoreError> {
        let session = self
            .sessions
            .read()
            .await
            .values()
            .find(|session| {
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
        let session = sessions.get_mut(code).ok_or(StoreError::NotFound)?;
        Self::ensure_fresh(session)?;
        if !matches!(session.state, SessionState::Pending { .. }) {
            return Err(StoreError::NotPending);
        }
        session.state = SessionState::Completed(CompletedSession {
            user: user.clone(),
            token,
            token_expires_at,
        });
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

    #[tokio::test]
    async fn session_creation_and_expiration() {
        let store = MemoryStore::new(Duration::from_millis(20));
        let session = store.create_session("client-state".into()).await;
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
    async fn session_completion_indexes_user() {
        let store = MemoryStore::new(Duration::from_secs(30));
        let session = store.create_session("state".into()).await;
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
