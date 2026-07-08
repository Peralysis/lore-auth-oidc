# Okta

Create an **OIDC - Web Application** integration in Okta.

1. Enable the authorization-code grant and add the exact `OIDC_REDIRECT_URL` as a sign-in redirect URI.
2. Use client-secret authentication and copy the generated credentials.
3. Select the issuer for the authorization server you intend to use, for example:

```dotenv
OIDC_ISSUER_URL=https://example.okta.com/oauth2/default
OIDC_SCOPES=openid profile email
OIDC_PROVIDER_NAME=okta
```

The org authorization server uses `https://example.okta.com`; a custom authorization server uses `/oauth2/{authorizationServerId}`. Do not mix discovery and authorization endpoints from different issuers. Standard profile claims normally provide `name`, `preferred_username`, and `email`.

A minimal Compose example is available at [compose/okta.yml](compose/okta.yml).

References: [Okta redirect-model web app guide](https://developer.okta.com/docs/guides/sign-into-web-app-redirect/), [authorization server issuer URIs](https://developer.okta.com/docs/concepts/auth-servers/).

