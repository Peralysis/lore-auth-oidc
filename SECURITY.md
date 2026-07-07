# Security policy

Please report suspected vulnerabilities privately to the project maintainers rather than opening a public issue. Do not include production tokens, signing keys, client secrets, or personal data in a report.

## Container release checklist

Before publishing an image:

1. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`.
2. Run `cargo audit` with a current RustSec database and review every exception below.
3. Build the pinned, multi-stage Dockerfile and scan the resulting image with an authenticated Docker Scout, Trivy, or equivalent scanner.
4. Publish by immutable digest, generate an SBOM/provenance attestation, and sign the digest with the registry's supported signing workflow.
5. Periodically update the pinned Rust, distroless, and Caddy digests to receive security fixes.

## Accepted advisory

`RUSTSEC-2023-0071` currently applies transitively through `openidconnect 4.0.1` and directly through `rsa 0.9.10`; no fixed `rsa` release is available. The timing attack concerns RSA private-key operations. This service uses the crate directly only to parse the adapter key and derive its public modulus/exponent, while `openidconnect` uses RSA public-key verification for provider ID tokens. Adapter JWT signing is performed by `jsonwebtoken` using ring. The vulnerable private-key operation is therefore not reachable in the current application path.

This is a scoped exception, not a permanent blanket ignore. Re-evaluate it whenever `openidconnect`, `rsa`, or JWT key handling changes, and remove it as soon as an upstream fixed dependency path is available.

**Re-verified 2026-07-06:** still no patched `rsa` release. RustSec continues to list the advisory as unpatched ("no patch is yet available"). The stable line remains `0.9.x`; a `0.10.0-rc.18` pre-release exists but is not designated as the fix. `openidconnect` is still at `4.0.1` and still pins `rsa 0.9` transitively, so upgrading it would not clear the finding today. The reachability analysis above was re-checked against `src/auth/jwt.rs` and still holds: `rsa` is used only for `RsaPrivateKey::from_pkcs8_pem`/`from_pkcs1_pem` → `to_public_key()` → `n()`/`e()` to publish the JWKS public key; signing still goes through `jsonwebtoken`'s `EncodingKey::from_rsa_pem` (ring). Exception stands; next re-check whenever `openidconnect`, `rsa`, or JWT key handling changes.

