use std::sync::Arc;

use tonic::{Request, Response, Status, metadata::MetadataMap};

use crate::{
    auth::jwt::{JwtService, authorizes_resource, resource_claims},
    proto::{self, urc_auth_api_server::UrcAuthApi},
    store::{SessionState, SessionStore, StoreError},
};

#[derive(Clone)]
pub struct AuthService {
    public_url: String,
    allow_all_users: bool,
    sessions: Arc<dyn SessionStore>,
    jwt: Arc<JwtService>,
}

impl AuthService {
    pub fn new(
        public_url: String,
        allow_all_users: bool,
        sessions: Arc<dyn SessionStore>,
        jwt: Arc<JwtService>,
    ) -> Self {
        Self {
            public_url: public_url.trim_end_matches('/').to_owned(),
            allow_all_users,
            sessions,
            jwt,
        }
    }

    #[allow(clippy::result_large_err)]
    fn bearer(metadata: &MetadataMap) -> Result<&str, Status> {
        metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Status::unauthenticated("missing Bearer token"))
    }

    fn map_store_error(error: StoreError) -> Status {
        match error {
            StoreError::NotFound => Status::not_found(error.to_string()),
            StoreError::Expired => Status::deadline_exceeded(error.to_string()),
            _ => Status::failed_precondition(error.to_string()),
        }
    }

    #[allow(clippy::result_large_err)]
    fn require_resource(&self, metadata: &MetadataMap, resource: &str) -> Result<(), Status> {
        let token = Self::bearer(metadata)?;
        let claims = self
            .jwt
            .validate_authz(token)
            .map_err(|_| Status::unauthenticated("invalid authorization token"))?;
        if authorizes_resource(&claims, resource) {
            Ok(())
        } else {
            Err(Status::permission_denied(
                "token does not authorize resource",
            ))
        }
    }
}

#[tonic::async_trait]
impl UrcAuthApi for AuthService {
    async fn health_check(
        &self,
        _request: Request<proto::HealthCheckRequest>,
    ) -> Result<Response<proto::HealthCheckResponse>, Status> {
        Ok(Response::new(proto::HealthCheckResponse {
            status: "SERVING".into(),
        }))
    }

    async fn start_auth_session(
        &self,
        request: Request<proto::StartAuthSessionRequest>,
    ) -> Result<Response<proto::StartAuthSessionResponse>, Status> {
        let session = self
            .sessions
            .create_session(request.into_inner().client_state)
            .await;
        Ok(Response::new(proto::StartAuthSessionResponse {
            login_url: format!("{}/login?session_code={}", self.public_url, session.code),
            session_code: session.code,
        }))
    }

    async fn get_auth_session(
        &self,
        request: Request<proto::GetAuthSessionRequest>,
    ) -> Result<Response<proto::GetAuthSessionResponse>, Status> {
        let request = request.into_inner();
        let session = self
            .sessions
            .get_session(&request.session_code)
            .await
            .map_err(Self::map_store_error)?;
        if session.client_state != request.client_state {
            return Err(Status::permission_denied("client_state does not match"));
        }
        let user_token = match session.state {
            SessionState::Pending { .. } => None,
            SessionState::Completed(completed) => Some(proto::UserToken {
                user_token: completed.token,
                expires_at: completed.token_expires_at,
                user_id: completed.user.user_id,
                user_name: completed.user.display_name,
            }),
        };
        Ok(Response::new(proto::GetAuthSessionResponse { user_token }))
    }

    async fn exchange_user_token_for_multiresource_token(
        &self,
        request: Request<proto::ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Result<Response<proto::ExchangeUserTokenForMultiresourceTokenResponse>, Status> {
        let bearer = Self::bearer(request.metadata())?;
        let authn = self
            .jwt
            .validate_authn(bearer)
            .map_err(|_| Status::unauthenticated("invalid authentication token"))?;
        let resources = resource_claims(&request.get_ref().resource_id, self.allow_all_users)
            .map_err(|error| {
                if self.allow_all_users {
                    Status::invalid_argument(error.to_string())
                } else {
                    Status::permission_denied(error.to_string())
                }
            })?;
        let (token, expires_at) = self
            .jwt
            .issue_authz(&authn, resources)
            .map_err(|_| Status::internal("failed to create authorization token"))?;
        Ok(Response::new(
            proto::ExchangeUserTokenForMultiresourceTokenResponse {
                token: Some(proto::UserToken {
                    user_token: token,
                    expires_at: expires_at * 1000,
                    user_id: authn.sub,
                    user_name: authn.name,
                }),
            },
        ))
    }

    async fn get_user_info(
        &self,
        request: Request<proto::GetUserInfoRequest>,
    ) -> Result<Response<proto::GetUserInfoResponse>, Status> {
        self.require_resource(request.metadata(), &request.get_ref().resource_id)?;
        let users = self.sessions.users_by_id(&request.get_ref().user_id).await;
        Ok(Response::new(proto::GetUserInfoResponse {
            user_info: users
                .into_iter()
                .map(|user| proto::UserInfo {
                    user_id: user.user_id,
                    display_name: user.display_name,
                })
                .collect(),
        }))
    }

    async fn get_user_id(
        &self,
        request: Request<proto::GetUserIdRequest>,
    ) -> Result<Response<proto::GetUserIdResponse>, Status> {
        self.require_resource(request.metadata(), &request.get_ref().resource_id)?;
        let user = self
            .sessions
            .user_by_display_name(&request.get_ref().user_display_name)
            .await;
        Ok(Response::new(proto::GetUserIdResponse {
            user_info: user.map(|user| proto::UserInfo {
                user_id: user.user_id,
                display_name: user.display_name,
            }),
        }))
    }

    async fn refresh_auth_session(
        &self,
        _request: Request<proto::RefreshAuthSessionRequest>,
    ) -> Result<Response<proto::RefreshAuthSessionResponse>, Status> {
        Err(Status::unimplemented("refresh sessions are not supported"))
    }

    async fn verify_user(
        &self,
        _request: Request<proto::VerifyUserRequest>,
    ) -> Result<Response<proto::VerifyUserResponse>, Status> {
        Err(Status::unimplemented("user verification is not supported"))
    }

    async fn exchange_external_token_for_user_token(
        &self,
        _request: Request<proto::ExchangeExternalTokenForUserTokenRequest>,
    ) -> Result<Response<proto::ExchangeExternalTokenForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "external token exchange is not supported",
        ))
    }

    async fn exchange_api_key_for_user_token(
        &self,
        _request: Request<proto::ExchangeApiKeyForUserTokenRequest>,
    ) -> Result<Response<proto::ExchangeApiKeyForUserTokenResponse>, Status> {
        Err(Status::unimplemented("API key exchange is not supported"))
    }

    async fn check_user_permission(
        &self,
        _request: Request<proto::CheckUserPermissionRequest>,
    ) -> Result<Response<proto::CheckUserPermissionResponse>, Status> {
        Err(Status::unimplemented("permission checks are not supported"))
    }

    async fn lookup_user_permissions(
        &self,
        _request: Request<proto::LookupUserPermissionsRequest>,
    ) -> Result<Response<proto::LookupUserPermissionsResponse>, Status> {
        Err(Status::unimplemented("permission lookup is not supported"))
    }

    async fn get_provider_user_id(
        &self,
        _request: Request<proto::GetProviderUserIdRequest>,
    ) -> Result<Response<proto::GetProviderUserIdResponse>, Status> {
        Err(Status::unimplemented("provider user IDs are not supported"))
    }
}
