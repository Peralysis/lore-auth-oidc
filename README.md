# lore-auth-oidc

`lore-auth-oidc` connects [Epic Games Lore](https://github.com/EpicGames/lore) to any standards-compatible OpenID Connect identity provider. It implements Lore's official gRPC authentication API, runs an OIDC authorization-code login, and issues Lore-compatible authentication and repository authorization JWTs.

The names belong to different protocol layers:

- Project and binary: `lore-auth-oidc`
- Lore auth URL scheme: `ucs-auth://`
- Official gRPC service: `UrcAuthApi`
- Protobuf package: `epic_urc`
- Lore resources: `urc-{repository_id}` and `urc-*`

> This protobuf is vendored from EpicGames/lore at `lore-proto/proto/auth_api.proto` and should be periodically synced with upstream Lore.

## Status

This MVP supports OIDC discovery, authorization code flow with PKCE, state and nonce validation, session polling, user-token exchange, user lookup, and JWKS publication. The session and user directory are in memory and are lost on restart. One process supports one OIDC issuer/client.

When `ALLOW_ALL_USERS=true`, authenticated users receive `read`, `write`, and `admin` on `urc-*`. The example defaults to `false`, which denies exchange until an authorization policy backend is implemented. Enable wildcard access only as an explicit MVP policy decision.

## Identity provider setup

Create a confidential OIDC web application at your provider. Enable authorization code flow, register the exact `OIDC_REDIRECT_URL`, and allow `openid profile email`. Provider-specific instructions:

- [Keycloak](docs/providers/keycloak.md)
- [Authentik](docs/providers/authentik.md)
- [Microsoft Entra ID](docs/providers/entra-id.md)
- [Auth0](docs/providers/auth0.md)
- [Okta](docs/providers/okta.md)
- [Amazon Cognito](docs/providers/cognito.md)

Other providers work when they publish standard OIDC discovery metadata, support confidential authorization-code clients with PKCE, and return an ID token.

## Configuration

Copy `.env.example` to `.env` and configure:

| Variable | Required | Purpose |
| --- | --- | --- |
| `ADAPTER_PUBLIC_URL` | yes | Public HTTPS origin used in Lore login URLs |
| `GRPC_BIND_ADDR` | yes | Internal tonic listener |
| `HTTP_BIND_ADDR` | yes | Internal axum listener |
| `OIDC_ISSUER_URL` | yes | Exact issuer advertised by OIDC discovery |
| `OIDC_CLIENT_ID` | yes | Confidential OIDC client ID |
| `OIDC_CLIENT_SECRET` or `OIDC_CLIENT_SECRET_FILE` | yes | Confidential OIDC client secret; file form is preferred in containers |
| `OIDC_REDIRECT_URL` | yes | Exact public `/callback` URL |
| `OIDC_SCOPES` | no | Space/comma-separated scopes; defaults to `openid profile email` |
| `OIDC_CLIENT_AUTH_METHOD` | no | `client_secret_basic` (default) or `client_secret_post` |
| `OIDC_DISPLAY_NAME_CLAIM` | no | Require this non-empty string claim as Lore display name |
| `OIDC_USERNAME_CLAIM` | no | Require this non-empty string claim as preferred username |
| `OIDC_PROVIDER_NAME` | no | Authz JWT `idp`; defaults to the issuer URL |
| `JWT_ISSUER` | yes | `iss` in adapter-issued Lore JWTs |
| `JWT_AUDIENCE` | yes | Lore server hostname accepted as `aud` |
| `JWT_PRIVATE_KEY_PATH` | yes | RSA PKCS#8 or PKCS#1 PEM signing key |
| `JWT_KEY_ID` | yes | Stable `kid` published through JWKS |
| `SESSION_TTL_SECONDS` | yes | Pending browser-login lifetime |
| `ALLOW_ALL_USERS` | yes | MVP wildcard authorization switch |
| `LORE_ENV` | yes | Lore environment encoded in JWTs |

OIDC `sub` is always the stable Lore user ID. Without overrides, display name resolves through `name`, `preferred_username`, `email`, then `sub`; username resolves through `preferred_username`, `email`, `name`, then `sub`. A configured override is strict: login fails if that claim is absent, empty, or not a string.

The former `KEYCLOAK_*` variables are intentionally unsupported; use `OIDC_*`.

## Run

Generate a development signing key:

```sh
mkdir -p secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out secrets/jwt-private.pem
printf '%s' 'your-oidc-client-secret' > secrets/oidc-client-secret
chmod 600 secrets/jwt-private.pem secrets/oidc-client-secret
```

Run directly with `cargo run`, or use the TLS-routing container example:

```sh
docker compose up --build
```

The Rust process exposes separate plaintext internal listeners. Lore converts `ucs-auth://auth.example.com` to HTTPS gRPC, so production must terminate TLS and route HTTP/2 gRPC and browser traffic on one hostname. The included Caddy configuration sends `application/grpc` to tonic and other requests to axum.

The Compose example mounts the JWT key and OIDC client secret through Compose secrets, runs the adapter with a read-only filesystem, drops Linux capabilities, and enables `no-new-privileges`. Environment-variable secrets remain supported for non-container deployments but can be exposed through container inspection, so prefer the `_FILE` setting in containers.

The Dockerfile uses digest-pinned Rust and distroless bases, produces a stripped release binary, and runs as the distroless non-root user. Digest pins intentionally require periodic updates; follow the release checklist in [SECURITY.md](SECURITY.md) rather than leaving them static indefinitely.

## Lore server configuration

```toml
[environment.endpoint]
auth_url = "ucs-auth://auth.example.com"

[server.auth]
jwt_issuer = "https://auth.example.com"
jwt_audience = ["lore.example.com"]

[server.auth.jwk]
endpoint = "https://auth.example.com/.well-known/jwks.json"
```

`JWT_ISSUER` and `JWT_AUDIENCE` must match these settings. JWT timestamps are Unix seconds; official protobuf `UserToken.expires_at` values are Unix milliseconds, as expected by Lore.

## Surfaces and development

- `GET /login?session_code=...`
- `GET /callback`
- `GET /.well-known/jwks.json`
- Official `epic_urc.UrcAuthApi` from `proto/auth_api.proto`

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for setup
and PR guidelines, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community
standards. Report suspected vulnerabilities privately per [SECURITY.md](SECURITY.md).

The project is licensed under MIT.
