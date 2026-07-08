# Amazon Cognito

Create an app client in a Cognito **user pool**; this adapter does not use Cognito identity pools.

1. Generate a client secret and enable authorization code grant.
2. Add the exact `OIDC_REDIRECT_URL` as an allowed callback URL.
3. Enable the `openid`, `profile`, and `email` scopes on the managed-login/hosted-UI client.
4. Use the user-pool issuer, not the hosted UI domain:

```dotenv
OIDC_ISSUER_URL=https://cognito-idp.REGION.amazonaws.com/USER_POOL_ID
OIDC_SCOPES=openid profile email
OIDC_PROVIDER_NAME=cognito
OIDC_USERNAME_CLAIM=cognito:username
```

`cognito:username` is a provider-specific ID-token claim and is supported by the generic claim override. The stable Lore user ID remains OIDC `sub`. Ensure the user pool exposes `name` or choose another display-name claim if names are not populated.

A minimal Compose example is available at [compose/cognito.yml](compose/cognito.yml).

References: [Cognito user-pool OIDC discovery and tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-id-token.html), [user-pool app clients](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html).
