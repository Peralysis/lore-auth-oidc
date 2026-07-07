# Auth0

Create a **Regular Web Application** in Auth0.

1. Add the exact `OIDC_REDIRECT_URL` under **Allowed Callback URLs**.
2. Copy the domain, client ID, and client secret from application settings.
3. Configure the tenant/custom-domain issuer with its trailing slash:

```dotenv
OIDC_ISSUER_URL=https://TENANT_REGION.auth0.com/
OIDC_SCOPES=openid profile email
OIDC_PROVIDER_NAME=auth0
OIDC_USERNAME_CLAIM=email
```

The username override is optional but useful because Auth0 commonly returns `nickname` and `email` rather than `preferred_username`. Use `nickname` instead if that is the desired Lore username. Custom Actions can add namespaced custom claims, which can also be selected by an override.

References: [Auth0 application settings](https://auth0.com/docs/get-started/applications/application-settings), [OIDC scopes and claims](https://auth0.com/docs/get-started/apis/scopes/openid-connect-scopes).

