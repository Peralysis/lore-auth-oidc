use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;

use crate::{
    auth::{jwt::JwtService, oidc::IdentityProvider},
    store::{OidcAttempt, SessionState, SessionStore},
};

#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<dyn SessionStore>,
    pub provider: Arc<dyn IdentityProvider>,
    pub jwt: Arc<JwtService>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/.well-known/jwks.json", get(jwks))
        .with_state(state)
}

#[derive(Deserialize)]
struct LoginQuery {
    session_code: String,
}

async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Redirect, WebError> {
    let session = state.sessions.get_session(&query.session_code).await?;
    if !matches!(session.state, SessionState::Pending { .. }) {
        return Err(WebError::bad_request("login session is already complete"));
    }
    let authorization = state.provider.authorization_url().await?;
    state
        .sessions
        .begin_oidc(
            &query.session_code,
            OidcAttempt {
                csrf_state: authorization.csrf_state,
                nonce: authorization.nonce,
                pkce_verifier: authorization.pkce_verifier,
            },
        )
        .await?;
    Ok(Redirect::temporary(&authorization.url))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Html<&'static str>, WebError> {
    if let Some(error) = query.error {
        let description = query.error_description.unwrap_or_default();
        return Err(WebError::bad_request(format!(
            "OIDC provider rejected login: {error} {description}"
        )));
    }
    let csrf_state = query.state.context("callback is missing state")?;
    let code = query.code.context("callback is missing code")?;
    let session = state.sessions.session_for_oidc_state(&csrf_state).await?;
    let attempt = match &session.state {
        SessionState::Pending {
            oidc: Some(attempt),
        } => attempt,
        _ => return Err(WebError::bad_request("OIDC login is not pending")),
    };
    let user = state
        .provider
        .exchange_code(&code, &attempt.nonce, &attempt.pkce_verifier)
        .await?;
    let (token, expires_at) = state.jwt.issue_authn(&user)?;
    state
        .sessions
        .complete_session(&session.code, user, token, expires_at * 1000)
        .await?;
    Ok(Html(
        "<!doctype html><title>Lore login complete</title><h1>Login complete</h1><p>You may close this window and return to Lore.</p>",
    ))
}

async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(state.jwt.jwks())
}

struct WebError {
    status: StatusCode,
    message: String,
}

impl WebError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl<E> From<E> for WebError
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        let error = error.into();
        tracing::warn!(error = ?error, "HTTP authentication request failed");
        Self::bad_request(error.to_string())
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        (
            self.status,
            Html(format!(
                "<!doctype html><title>Login error</title><h1>Login error</h1><p>{}</p>",
                escape_html(&self.message)
            )),
        )
            .into_response()
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
