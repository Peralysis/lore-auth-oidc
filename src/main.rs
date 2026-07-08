use std::sync::Arc;

use anyhow::{Context, Result};
use lore_auth_oidc::{
    auth::{
        jwt::JwtService,
        oidc::{OidcOptions, OidcProvider},
    },
    config::Config,
    grpc::AuthService,
    http::{AppState, router},
    proto::urc_auth_api_server::UrcAuthApiServer,
    store::MemoryStore,
};
use tokio::sync::broadcast;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env()?;
    let jwt = Arc::new(JwtService::from_path(
        &config.jwt_private_key_path,
        config.jwt_key_id.clone(), // None derives the RFC 7638 JWK thumbprint
        config.jwt_issuer.clone(),
        config.jwt_audience.clone(),
        config.lore_env.clone(),
        config.oidc_provider_name.clone(),
    )?);
    let sessions = Arc::new(MemoryStore::new(config.session_ttl));
    let provider = Arc::new(OidcProvider::new(OidcOptions {
        issuer_url: config.oidc_issuer_url.clone(),
        client_id: config.oidc_client_id.clone(),
        client_secret: config.oidc_client_secret.clone(),
        redirect_url: config.oidc_redirect_url.clone(),
        scopes: config.oidc_scopes.clone(),
        display_name_claim: config.oidc_display_name_claim.clone(),
        username_claim: config.oidc_username_claim.clone(),
        client_auth_method: config.oidc_client_auth_method,
        tls_root_ca_pem: config.oidc_tls_root_ca.clone(),
    })?);
    provider
        .preload()
        .await
        .context("initial OIDC discovery failed; check OIDC_ISSUER_URL and network access to the identity provider")?;
    tracing::info!(issuer = %config.oidc_issuer_url, kid = jwt.key_id(), "OIDC discovery succeeded");

    let grpc_service = AuthService::new(
        config.adapter_public_url.to_string(),
        config.allow_all_users,
        sessions.clone(),
        jwt.clone(),
    );
    let http_router = router(AppState {
        sessions,
        provider,
        jwt,
    });

    let http_listener = tokio::net::TcpListener::bind(config.http_bind_addr)
        .await
        .context("failed to bind HTTP listener")?;
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let mut grpc_shutdown = shutdown_tx.subscribe();
    let mut http_shutdown = shutdown_tx.subscribe();

    tracing::info!(address = %config.grpc_bind_addr, "gRPC listener started");
    tracing::info!(address = %config.http_bind_addr, "HTTP listener started");

    let grpc = Server::builder()
        .add_service(UrcAuthApiServer::new(grpc_service))
        .serve_with_shutdown(config.grpc_bind_addr, async move {
            let _ = grpc_shutdown.recv().await;
        });
    let http = async move {
        axum::serve(http_listener, http_router)
            .with_graceful_shutdown(async move {
                let _ = http_shutdown.recv().await;
            })
            .await
    };

    tokio::pin!(grpc);
    tokio::pin!(http);
    tokio::select! {
        result = &mut grpc => result.context("gRPC server failed")?,
        result = &mut http => result.context("HTTP server failed")?,
        result = tokio::signal::ctrl_c() => result.context("failed to listen for shutdown signal")?,
    }
    let _ = shutdown_tx.send(());
    Ok(())
}
