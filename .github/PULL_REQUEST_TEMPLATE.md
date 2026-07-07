## Summary

<!-- What does this change do, and why? -->

## Related issue

<!-- Fixes #, Closes #, or Relates to # -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Provider setup docs (`docs/providers/`)
- [ ] Dependency / build / CI change
- [ ] Vendored protobuf resync (`proto/auth_api.proto`)
- [ ] Other (describe above)

## Security impact

- [ ] This change touches claim resolution, token issuance, session handling, or authorization policy
- [ ] This change touches secret handling (JWT signing key, OIDC client secret)
- [ ] No security-relevant impact

If any box above is checked, describe the impact and how it was verified.

## Test plan

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `cargo build --release`
- [ ] Manually verified against a real OIDC provider (specify which):

## Checklist

- [ ] I have updated `README.md` / relevant `docs/providers/*.md` if configuration or setup changed
- [ ] I have not committed secrets, private keys, or `.env` files
