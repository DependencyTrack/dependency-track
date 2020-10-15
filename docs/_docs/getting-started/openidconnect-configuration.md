---
title: OpenID Connect Configuration
category: Getting Started
chapter: 1
order: 9
---

> OpenID Connect is supported in Dependency-Track 4.0.0 and above

In the context of OAuth2 / OIDC, Dependency-Track's frontend acts as client while the backend acts as resource server (see [OAuth2 roles](https://tools.ietf.org/html/rfc6749#section-1.1)).
Due to this, the frontend requires additional configuration, which is currently only supported when deploying it separately from the backend.
Refer to the [Docker deployment page]({{ site.baseurl }}{% link _docs/getting-started/deploy-docker.md %}) or the [frontend's GitHub repository](https://github.com/DependencyTrack/frontend/blob/master/README.md) for instructions.

If configured properly, users will be able to sign in by clicking the *OpenID* button on the login page:
![Login page with OpenID button](/images/screenshots/oidc-login-page.png)

| Backend                                                         | Frontend                                                 |
|:----------------------------------------------------------------|:---------------------------------------------------------|
| ALPINE_OIDC_ENABLED=true                                        | OIDC_CLIENT_ID=dependency-track                          |
| ALPINE_OIDC_ISSUER=https://auth.example.com/auth/realms/example | OIDC_ISSUER=https://auth.example.com/auth/realms/example |
| ALPINE_OIDC_USERNAME_CLAIM=preferred_username                   | OIDC_FLOW=code                                           |
| ALPINE_OIDC_USER_PROVISIONING=true                              |                                                          |
| ALPINE_OIDC_TEAMS_CLAIM=groups                                  |                                                          |
| ALPINE_OIDC_TEAM_SYNCHRONIZATION=true                           |                                                          |

### Prerequisites

* Issuer URL
* openid-configuration endpoint
* CORS headers
* Name of the username claim
* Name of the teams claim

#### Scopes

Some identity providers require configuration of the scopes a client can request. 
Dependency-Track will request access tokens with the following scopes during the authentication process:

| Scope   | Reason                                                                  |
|:--------|:------------------------------------------------------------------------|
| openid  | Required for OpenID Connect based authentication                        |
| profile | Required for access to the user's name (+ roles and group memberships)  |
| email   | Required for access to the user's email address                         |

### Example Configurations

Dependency-Track can be used with any identity provider that implements the [OpenID Connect](https://openid.net/connect/) standard.

Multiple identity providers have been tested, the following are some example configurations that are known to work. 
If you find that the provider of your choice does not work with Dependency-Track, please [file an issue](https://github.com/DependencyTrack/dependency-track/issues).

#### Auth0

| Backend                                                        | Frontend                                        |
|:---------------------------------------------------------------|:------------------------------------------------|
| alpine.oidc.issuer=https://example.auth0.com                   | OIDC_CLIENT_ID=9XgMg7bP7QbD74TZnzZ9Jhk9KHq3RPCM |
| alpine.oidc.username.claim=nickname                            | OIDC_ISSUER=https://example.auth0.com           |
| alpine.oidc.teams.claim=groups<span style="color:red">*</span> |                                                 |

<span style="color:red">*</span> Requires additional configuration

#### GitLab (gitlab.com)

| Backend                               | Frontend                        |
|:--------------------------------------|:--------------------------------|
| alpine.oidc.issuer=https://gitlab.com | OIDC_CLIENT_ID=dependency-track |
| alpine.oidc.username.claim=nickname   | OIDC_ISSUER=https://gitlab.com  |
| alpine.oidc.teams.claim=groups        |                                 |

> gitlab.com currently does not set the required CORS headers, see GitLab issue [#209259](https://gitlab.com/gitlab-org/gitlab/-/issues/209259).  
> For on-premise installations, this could be fixed by setting the required headers via reverse proxy.  

#### Keycloak

| Backend                                                         | Frontend                                                 |
|:----------------------------------------------------------------|:---------------------------------------------------------|
| alpine.oidc.issuer=https://auth.example.com/auth/realms/example | OIDC_CLIENT_ID=dependency-track                          |
| alpine.oidc.username.claim=preferred_username                   | OIDC_ISSUER=https://auth.example.com/auth/realms/example |
| alpine.oidc.teams.claim=groups<span style="color:red">*</span>  |                                                          |

<span style="color:red">*</span> Requires additional configuration

### Example setup with Keycloak

This guide demonstrates how to configure OpenID Connect with Keycloak. Most steps should be applicable to other IdPs as well.

> This guide assumes that the Dependency-Track frontend has been deployed to `http://dependencytrack.example.com`.

1. Configure the client as shown below:
![Keycloak: Configure client](/images/screenshots/oidc-keycloak-client-settings.png)
  * Client ID: `dependency-track`
  * Access Type: `public`
  * Standard Flow Enabled: `ON`
  * Valid Redirect URIs: `<DTRACK_FRONTEND_URL>/static/oidc-callback.html`
  * Web Origins: `<DTRACK_FRONTEND_URL>`

2. To be able to synchronize team memberships, create a *protocol mapper* that includes group memberships as `groups` in
the /userinfo endpoint:
![Keycloak: Create protocol mapper for groups](/images/screenshots/oidc-keycloak-create-protocol-mapper.png) 
  * Mapper Type: `Group Membership`
  * Token Claim Name: `groups`
  * Add to userinfo: `ON`

3. Create some groups, e.g. `DTRACK_ADMINS` and `DTRACK_USERS`:
![Keycloak: Groups](/images/screenshots/oidc-keycloak-groups.png)

4. Verify that all required claims are present in the /userinfo endpoint
  * Acquire an access token for a user and call /userinfo with it
  * You can temporarily set *Direct Access Grants Enabled* to `ON` in the client settings to enable the [Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3)
```
$ ACCESS_TOKEN=$(curl https://auth.example.com/auth/realms/example/protocol/openid-connect/token \
    -d "client_id=dependency-track" \
    -d "grant_type=password" \
    -d "username=demo-user" \
    -d "password=demo-pass" \
    | jq -r .access_token)
$ curl https://auth.example.com/auth/realms/example/protocol/openid-connect/userinfo \
    -H "Authorization: Bearer $ACCESS_TOKEN"
```
  * The response should look similar to this:
```json
{
  "groups": ["DTRACK_USERS"],
  "sub": "290e5d27-25d2-414c-a04c-5d03cd0e1db8",
  "email_verified": true,
  "preferred_username": "demo-user",
  "email": "demo@example.com"
}
```

4. Login to Dependency-Track as `admin` and navigate to *Administration -> Access Management -> OpenID Connect Groups*
  * Create groups with names equivalent to those in Keycloak
  * Add teams that the groups should be mapped to
![Group mappings](/images/screenshots/oidc-groups.png)
