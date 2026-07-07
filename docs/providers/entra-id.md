# Microsoft Entra ID

Register a web application in Microsoft Entra ID.

1. Under **Authentication**, add the exact `OIDC_REDIRECT_URL` as a **Web** redirect URI.
2. Under **Certificates & secrets**, create a client secret and store its value immediately.
3. Use the application (client) ID and a tenant-specific v2.0 issuer:

```dotenv
OIDC_ISSUER_URL=https://login.microsoftonline.com/TENANT_ID/v2.0
OIDC_SCOPES=openid profile email
OIDC_CLIENT_AUTH_METHOD=client_secret_post
OIDC_PROVIDER_NAME=entra-id
```

Use a tenant ID or verified tenant domain rather than `common`: the returned token issuer must exactly match discovery for validation. Entra normally exposes `name` and `preferred_username`; the latter is displayable but must not replace the stable `sub` user ID.

References: [Microsoft identity platform OIDC protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc), [register a web application](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app).
