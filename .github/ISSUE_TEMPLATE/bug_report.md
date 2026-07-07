---
name: Bug report
about: Report a problem with lore-auth-oidc
title: "[Bug] "
labels: bug
assignees: ''
---

## Describe the bug

A clear and concise description of what's wrong.

## Environment

- `lore-auth-oidc` version / commit:
- OIDC provider (Keycloak, Authentik, Entra ID, Auth0, Okta, Cognito, other):
- Deployment method (`cargo run`, `docker compose`, other):
- OS / architecture:

## Configuration

Relevant `.env` settings (**redact secrets, client IDs, and signing keys**):

```
OIDC_ISSUER_URL=
ALLOW_ALL_USERS=
...
```

## Steps to reproduce

1.
2.
3.

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Include relevant log output (redact tokens, secrets,
and personal data) and, if applicable, the gRPC or HTTP error returned.

## Additional context

Anything else that might help diagnose the issue.

---

**Security note:** if this bug is a suspected vulnerability (e.g. token
forgery, authorization bypass, secret exposure), do not file it here — follow
the private reporting process in [SECURITY.md](../../SECURITY.md) instead.
