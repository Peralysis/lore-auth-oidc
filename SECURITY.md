# Security policy

Please report suspected vulnerabilities privately to the project maintainers rather than opening a public issue. Do not include production tokens, signing keys, client secrets, or personal data in a report.

## Container release checklist

Before publishing an image:

1. Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`.
2. Run `cargo audit` with a current RustSec database and review any exceptions.
3. Build the pinned, multi-stage Dockerfile and scan the resulting image with an authenticated Docker Scout, Trivy, or equivalent scanner.
4. Publish by immutable digest, generate an SBOM/provenance attestation, and sign the digest with the registry's supported signing workflow.
5. Periodically update the pinned Rust, distroless, and Caddy digests to receive security fixes.

