FROM rust:1.96-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:b0ae8e989418b458e0f25489bc3be523718938a2b70864cc0f6a00af1ddbd985
LABEL org.opencontainers.image.title="lore-auth-oidc" \
      org.opencontainers.image.description="OpenID Connect authentication adapter for Epic Games Lore" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder --chown=65532:65532 /app/target/release/lore-auth-oidc /usr/local/bin/lore-auth-oidc
USER 65532:65532
EXPOSE 50051 8080
ENTRYPOINT ["/usr/local/bin/lore-auth-oidc"]
