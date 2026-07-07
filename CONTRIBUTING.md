# Contributing to lore-auth-oidc

Thanks for your interest in contributing. This project is an OIDC
authentication adapter for [Epic Games Lore](https://github.com/EpicGames/lore),
so changes here can affect production login flows and issued JWTs — please
read this guide before opening a pull request.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.

## Reporting security issues

Do not open a public issue for suspected vulnerabilities. Follow the private
reporting process in [SECURITY.md](SECURITY.md) instead.

## Getting started

1. Fork and clone the repository.
2. Copy `.env.example` to `.env` and fill in an OIDC provider's confidential
   client credentials (see the provider guides in `docs/providers/`).
3. Generate a development JWT signing key:

   ```sh
   mkdir -p secrets
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out secrets/jwt-private.pem
   printf '%s' 'your-oidc-client-secret' > secrets/oidc-client-secret
   chmod 600 secrets/jwt-private.pem secrets/oidc-client-secret
   ```

4. Run the adapter with `cargo run`, or `docker compose up --build` for the
   TLS-routing container example.

## Making changes

- Keep changes focused; unrelated refactors make review harder.
- Match the existing code style — no new abstractions or config knobs unless
  the change genuinely needs them.
- If you touch claim resolution, token issuance, or authorization logic,
  explain the security implications in your PR description.
- Update `README.md` and the relevant `docs/providers/*.md` guide if you
  change configuration, environment variables, or provider setup steps.

## Before opening a pull request

Run the full local check suite:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

If your change touches dependencies, also run `cargo audit` and review any
findings against the accepted-advisory notes in [`.cargo/audit.toml`](.cargo/audit.toml).

## Commit messages & releases

Releases are automated: [release-please](https://github.com/googleapis/release-please)
watches `main`, opens a release PR that bumps the version and updates
`CHANGELOG.md`, and CI publishes the container image to GHCR when that PR is
merged. This only works if commits follow
[Conventional Commits](https://www.conventionalcommits.org/):

- `feat: ...` — new feature (minor version bump).
- `fix: ...` — bug fix (patch version bump).
- `feat!: ...` / a `BREAKING CHANGE:` footer — breaking change (major bump).
- `chore:`, `docs:`, `refactor:`, `test:`, `ci:`, `build:` — no release
  triggered; still useful for a readable history.

**Security-relevant dependency bumps must use `fix(deps):` and put the
advisory ID in the subject line**, e.g.:

```
fix(deps): bump jsonwebtoken to 10.4.0 (CVE-2026-25537)
```

release-please's changelog entries are generated from the commit subject, not
the body, so this is what makes the CVE/GHSA ID show up in `CHANGELOG.md` and
the GitHub Release notes. A commit like `chore(deps): bump jsonwebtoken` would
neither trigger a release nor surface the ID anywhere.

## Pull requests

- Use the PR template and fill in the test plan.
- Reference any related issue.
- Keep commits meaningful and Conventional-Commits-formatted; squash fixup
  commits before requesting review.
- A maintainer will review and may request changes before merging.

## Vendored protobuf

`proto/auth_api.proto` is vendored from `EpicGames/lore`. Do not hand-edit it;
resync from upstream Lore instead, and note the sync in your PR description.
