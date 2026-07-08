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

When `ALLOW_ALL_USERS=true`, authenticated users receive `read`, `write`, and `admin` on exactly the `urc-{repository_id}` resources their client requests during token exchange. It defaults to `false`, which denies exchange until an authorization policy backend is implemented. Enable it only as an explicit MVP policy decision.

## Identity provider setup

Create a confidential OIDC web application at your provider. Enable authorization code flow, register the exact `OIDC_REDIRECT_URL`, and allow `openid profile email`. Provider-specific instructions:

- [Keycloak](docs/providers/keycloak.md)
- [Authentik](docs/providers/authentik.md)
- [Microsoft Entra ID](docs/providers/entra-id.md)
- [Auth0](docs/providers/auth0.md)
- [Okta](docs/providers/okta.md)
- [Amazon Cognito](docs/providers/cognito.md)

Each guide links a minimal Compose example in [docs/providers/compose/](docs/providers/compose/) with that provider's environment pre-filled. Other providers work when they publish standard OIDC discovery metadata, support confidential authorization-code clients with PKCE, and return an ID token.

## Configuration

Copy `.env.example` to `.env` and configure. Six variables are required; everything else has a sensible default or is derived from `ADAPTER_PUBLIC_URL`:

| Variable | Required | Purpose |
| --- | --- | --- |
| `ADAPTER_PUBLIC_URL` | yes | Public HTTPS origin used in Lore login URLs |
| `OIDC_ISSUER_URL` | yes | Exact issuer advertised by OIDC discovery |
| `OIDC_CLIENT_ID` | yes | Confidential OIDC client ID |
| `OIDC_CLIENT_SECRET` or `OIDC_CLIENT_SECRET_FILE` | yes | Confidential OIDC client secret; file form is preferred in containers |
| `JWT_AUDIENCE` | yes | Lore server hostname(s) accepted as `aud`; comma/space-separated for a server reachable under multiple aliases (e.g. `localhost,127.0.0.1`) |
| `JWT_PRIVATE_KEY_PATH` | yes | RSA PKCS#8 or PKCS#1 PEM signing key |
| `OIDC_REDIRECT_URL` | no | Public `/callback` URL; defaults to `{ADAPTER_PUBLIC_URL}/callback` |
| `JWT_ISSUER` | no | `iss` in adapter-issued Lore JWTs; defaults to `ADAPTER_PUBLIC_URL` |
| `JWT_KEY_ID` | no | `kid` published through JWKS; defaults to the key's RFC 7638 JWK thumbprint |
| `GRPC_BIND_ADDR` | no | Internal tonic listener; defaults to `0.0.0.0:50051` |
| `HTTP_BIND_ADDR` | no | Internal axum listener; defaults to `0.0.0.0:8080` |
| `OIDC_SCOPES` | no | Space/comma-separated scopes; defaults to `openid profile email` |
| `OIDC_CLIENT_AUTH_METHOD` | no | `client_secret_basic` (default) or `client_secret_post` |
| `OIDC_DISPLAY_NAME_CLAIM` | no | Require this non-empty string claim as Lore display name |
| `OIDC_USERNAME_CLAIM` | no | Require this non-empty string claim as preferred username |
| `OIDC_PROVIDER_NAME` | no | Authz JWT `idp`; defaults to the issuer URL |
| `OIDC_TLS_ROOT_CA_FILE` | no | Extra PEM root CA bundle to trust when the issuer uses a private CA |
| `SESSION_TTL_SECONDS` | no | Pending browser-login lifetime; defaults to `600` |
| `ALLOW_ALL_USERS` | no | MVP authorization switch; defaults to `false` |
| `LORE_ENV` | no | Lore environment encoded in JWTs; defaults to `production` |

The adapter runs OIDC discovery at startup and exits with a clear error when `OIDC_ISSUER_URL` is wrong or unreachable, rather than failing on the first login attempt. If the identity provider sits behind a reverse proxy or TLS-terminating gateway with a private CA, point `OIDC_TLS_ROOT_CA_FILE` at a PEM bundle of the additional root certificates; the system roots remain trusted alongside them.

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

`JWT_ISSUER` and `JWT_AUDIENCE` must match these settings — if the Lore server is reachable under more than one hostname (e.g. `localhost` and `127.0.0.1` for the same local deployment), list all of them in both `JWT_AUDIENCE` and `jwt_audience`; a token is valid for any hostname a client used to reach it, not just the first. JWT timestamps are Unix seconds; official protobuf `UserToken.expires_at` values are Unix milliseconds, as expected by Lore.

## Surfaces and development

- `GET /login?session_code=...`
- `GET /callback`
- `GET /.well-known/jwks.json`
- `GET /healthz`
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
