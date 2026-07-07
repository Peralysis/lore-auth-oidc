# Keycloak

Create an OpenID Connect client in the target realm using the confidential-client authorization code flow.

1. Set **Client authentication** on and enable the **Standard flow**.
2. Add the exact `OIDC_REDIRECT_URL` under **Valid redirect URIs**.
3. Copy the client ID and secret into `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`.
4. Use the realm issuer and keep the default scopes:

```dotenv
OIDC_ISSUER_URL=https://keycloak.example.com/realms/lore
OIDC_SCOPES=openid profile email
OIDC_PROVIDER_NAME=keycloak
```

Keycloak normally supplies `name`, `preferred_username`, and `email` through its built-in client scopes. If a realm has customized scopes or mappers, ensure these claims are present or set the claim overrides explicitly.

References: [Keycloak OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers), [Keycloak server administration](https://www.keycloak.org/docs/latest/server_admin/).

