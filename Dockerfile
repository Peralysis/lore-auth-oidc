FROM rust:1.96-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home adapter
COPY --from=builder /app/target/release/lore-auth-oidc /usr/local/bin/lore-auth-oidc
USER adapter
EXPOSE 50051 8080
ENTRYPOINT ["lore-auth-oidc"]
