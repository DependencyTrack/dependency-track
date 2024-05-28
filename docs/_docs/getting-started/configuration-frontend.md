---
title: Configuration - Frontend
category: Getting Started
chapter: 1
order: 7
---

The frontend uses a static `config.json` file that is dynamically requested and evaluated via AJAX.
This file resides in `<BASE_URL>/static/config.json`.

#### Default configuration

```json
{
    // Required
    // The base URL of the API server.
    // NOTE:
    //   * This URL must be reachable by the browsers of your users.
    //   * The frontend container itself does NOT communicate with the API server directly, it just serves static files.
    //   * When deploying to dedicated servers, please use the external IP or domain of the API server.
    "API_BASE_URL": "",
    // Optional
    // Defines the issuer URL to be used for OpenID Connect.
    // See alpine.oidc.issuer property of the API server.
    "OIDC_ISSUER": "",
    // Optional
    // Defines the client ID for OpenID Connect.
    "OIDC_CLIENT_ID": "",
    // Optional
    // Defines the scopes to request for OpenID Connect.
    // See also: https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
    "OIDC_SCOPE": "openid profile email",
    // Optional
    // Specifies the OpenID Connect flow to use.
    // Values other than "implicit" will result in the Code+PKCE flow to be used.
    // Usage of the implicit flow is strongly discouraged, but may be necessary when
    // the IdP of choice does not support the Code+PKCE flow.
    // See also:
    //   - https://oauth.net/2/grant-types/implicit/
    //   - https://oauth.net/2/pkce/
    "OIDC_FLOW": "",
    // Optional
    // Defines the text of the OpenID Connect login button. 
    "OIDC_LOGIN_BUTTON_TEXT": ""
}
```

For containerized deployments, these settings can be overwritten by either:

* mounting a customized `config.json` to `/app/static/config.json` inside the container
* providing them as environment variables

The names of the environment variables are equivalent to their counterparts in `config.json`.

#### Base path

For containerized deployments the environment variable `BASE_PATH` is also available to set the base path of the frontend.
This configures nginx to serve the frontend from a subdirectory. For example, if the frontend is served from `https://example.com/dependency-track`, you would set `BASE_PATH` to `/dependency-track`.

> A mounted `config.json` takes precedence over environment variables.
> If both are provided, environment variables will be ignored.
