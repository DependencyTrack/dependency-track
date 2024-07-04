---
title: OpenID Connect Configuration
category: Getting Started
chapter: 1
order: 11
---

> OpenID Connect is supported in Dependency-Track 4.0.0 and above

In the context of OAuth2 / OIDC, Dependency-Track's frontend acts as _client_ while the API server acts as _resource server_ (see [OAuth2 roles](https://tools.ietf.org/html/rfc6749#section-1.1)).
Due to this, the frontend requires additional configuration, which is currently only supported when deploying it separately from the API server.
Refer to the [Configuration]({{ site.baseurl }}{% link _docs/getting-started/configuration.md %}) and [Docker deployment]({{ site.baseurl }}{% link _docs/getting-started/deploy-docker.md %}) pages for instructions. The “bundled” Docker image and "Classic" Dependency-Track deployments using solely the [executable WAR]({{ site.baseurl }}{% link _docs/getting-started/deploy-exewar.md %}) are not supported!

If configured properly, users will be able to sign in by clicking the _OpenID_ button on the login page:

![Login page with OpenID button](/images/screenshots/oidc-login-page.png)

> **NOTE:** the front-end will *not* display the OIDC login button if the Dependency-Track service is unable to connect to your OIDC server's `.well-known/openid-configuration` endpoint. The server logs can help you identify whether this is an issue with firewall rules, internal TLS certificates, or other errors which may be preventing that communication.

> Before v4.3.0, Dependency-Track exclusively used the `/userinfo` endpoint of the IdP to get user information.  
> Since v4.3.0, [ID tokens](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) are validated and evaluated as well. They even take precedence over `/userinfo`,  
> which means that Dependency-Track will no longer request the `/userinfo` endpoint if all required claims  
> are present in the ID token's payload already.

## How OpenID Connect claims are mapped

When someone authenticates using OIDC, the claims provided in the ID token or `/userinfo` API response will be mapped to existing OIDC Groups and the user will be added to any teams which have those groups mapped. To have OIDC users added to a team, you must perform the following steps:

1. Login to Dependency-Track as an administrator and navigate to _Administration_ -> _Access Management_ -> _OpenID Connect Groups_.
2. Create a group with the name used in the OIDC team claim configured below. The value _must_ match exactly, including case.
3. If the team you want members of the OIDC group to join already exists, use the _Mapped Teams_ menu to select it. If the team does not exist, open _Administration_ -> _Access Management_ -> _Teams_ to create it and, after having done so, add the OIDC group to the _Mapped OpenID Connect Groups_ list.

### Example Configurations

Generally, Dependency-Track can be used with any identity provider that implements the [OpenID Connect](https://openid.net/connect/) standard.
Multiple identity providers have been tested, the following are some example configurations that are known to work.
Note that some providers may not support specific features like team synchronization, or require further configuration to make them work.
If you find that the provider of your choice does not work with Dependency-Track, please [file an issue](https://github.com/DependencyTrack/dependency-track/issues).

For a complete overview of available configuration options for both API server and frontend, please refer to the [Configuration page]({{ site.baseurl }}{% link _docs/getting-started/configuration.md %}).

#### Auth0

| API server                                                             | Frontend                                        |
| :--------------------------------------------------------------------- | :---------------------------------------------- |
| alpine.oidc.enabled=true                                               |                                                 |
| alpine.oidc.client.id=9XgMg7bP7QbD74TZnzZ9Jhk9KHq3RPCM                 | OIDC_CLIENT_ID=9XgMg7bP7QbD74TZnzZ9Jhk9KHq3RPCM |
| alpine.oidc.issuer=https://example.auth0.com                           | OIDC_ISSUER=https://example.auth0.com           |
| alpine.oidc.username.claim=nickname                                    |                                                 |
| alpine.oidc.user.provisioning=true                                     |                                                 |
| alpine.oidc.teams.claim=groups<span style="color:red">\*</span>        |                                                 |
| alpine.oidc.team.synchronization=true<span style="color:red">\*</span> |                                                 |

<span style="color:red">\*</span> Requires [additional configuration](https://auth0.com/docs/extensions/authorization-extension/use-rules-with-the-authorization-extension)

#### GitLab (gitlab.com)

| API server                                                                             | Frontend                                                                        |
| :------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------ |
| alpine.oidc.enabled=true                                                               |                                                                                 |
| alpine.oidc.client.id=ff53529a3806431e06b2930c07ab0275a9024a59873a0d5106dd67c4cd34e3be | OIDC_CLIENT_ID=ff53529a3806431e06b2930c07ab0275a9024a59873a0d5106dd67c4cd34e3be |
| alpine.oidc.issuer=https://gitlab.com                                                  | OIDC_ISSUER=https://gitlab.com                                                  |
| alpine.oidc.username.claim=nickname                                                    |                                                                                 |
| alpine.oidc.user.provisioning=true                                                     |                                                                                 |
| alpine.oidc.teams.claim=groups                                                         |                                                                                 |
| alpine.oidc.team.synchronization=true                                                  |                                                                                 |

> gitlab.com currently does not set the required CORS headers, see GitLab issue [#209259](https://gitlab.com/gitlab-org/gitlab/-/issues/209259).  
> For on-premise installations, this could be fixed by setting the required headers via reverse proxy.

#### Azure Active Directory

| API server                                                                                     | Frontend                                                                                |
| :--------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------- |
| alpine.oidc.enabled=true                                                                       |                                                                                         |
| alpine.oidc.client.id=2e0a07ae-eabd-45d7-a8f5-ca4ad71b48ae                                     | OIDC_CLIENT_ID=2e0a07ae-eabd-45d7-a8f5-ca4ad71b48ae                                     |
| alpine.oidc.issuer=https://login.microsoftonline.com/3919df77-d4cd-4772-8b50-cfdb195bcdd6/v2.0 | OIDC_ISSUER=https://login.microsoftonline.com/3919df77-d4cd-4772-8b50-cfdb195bcdd6/v2.0 |
| alpine.oidc.username.claim=preferred_username                                                  |                                                                                         |
| alpine.oidc.user.provisioning=true                                                             |                                                                                         |
| alpine.oidc.teams.claim=groups                                                                 |                                                                                         |
| alpine.oidc.team.synchronization=true                                                          |                                                                                         |

OIDC integration with Azure Active Directory requires you to register Dependency-Track as an app in your tenant, see [Azure Active Directory app registration](#azure-active-directory-app-registration).

The `alpine.oidc.client.id` contains the Application ID of the app registration, and the `alpine.oidc.issuer` contains the Directory (tenant) ID.

#### Google

| API server                                     | Frontend                                |
| :--------------------------------------------- | :-------------------------------------- |
| alpine.oidc.enabled=true                       |                                         |
| alpine.oidc.client.id=<Google client id>       | OIDC_CLIENT_ID=<Google client id>       |
| alpine.oidc.issuer=https://accounts.google.com | OIDC_ISSUER=https://accounts.google.com |
| alpine.oidc.username.claim=email               | OIDC_FLOW=implicit                      |
| alpine.oidc.user.provisioning=true             |                                         |

Follow the [docs](https://support.google.com/cloud/answer/6158849?hl=en) to learn how to create the client id.

Set the redirect URI to `<dependency track host>/static/oidc-callback.html`

#### Keycloak

| API server                                                             | Frontend                                                 |
| :--------------------------------------------------------------------- | :------------------------------------------------------- |
| alpine.oidc.enabled=true                                               |                                                          |
| alpine.oidc.client.id=dependency-track                                 | OIDC_CLIENT_ID=dependency-track                          |
| alpine.oidc.issuer=https://auth.example.com/auth/realms/example        | OIDC_ISSUER=https://auth.example.com/auth/realms/example |
| alpine.oidc.username.claim=preferred_username                          |                                                          |
| alpine.oidc.user.provisioning=true                                     |                                                          |
| alpine.oidc.teams.claim=groups<span style="color:red">\*</span>        |                                                          |
| alpine.oidc.team.synchronization=true<span style="color:red">\*</span> |                                                          |

<span style="color:red">\*</span> Requires additional configuration, see [Example setup with Keycloak](#example-setup-with-keycloak)

#### OneLogin

| API server                                                                                  | Frontend                                                                                   |
| :------------------------------------------------------------------------------------------ | :----------------------------------------------------------------------------------------- |
| alpine.oidc.enabled=true                                                                    |                                                                                            |
| alpine.oidc.client.id=a9eb980a-fake-45f9-96e0-0891ff63d00d<span style="color:red">\*</span> | OIDC_CLIENT_ID=a9eb980a-fake-45f9-96e0-0891ff63d00d<span style="color:red">\*</span>       |
| alpine.oidc.issuer=https://example.onelogin.com/oidc/2                                      | OIDC_ISSUER=https://example.onelogin.com/oidc/2                                            |
| alpine.oidc.username.claim=email                                                            |                                                                                            |
| alpine.oidc.user.provisioning=true                                                          |                                                                                            |
| alpine.oidc.teams.claim=groups                                                              | OIDC_SCOPE=openid profile email groups                                                     |
| alpine.oidc.team.synchronization=true                                                       |                                                                                            |

<span style="color:red">\*</span> Requires additional configuration, see [Example setup with OneLogin](#example-setup-with-onelogin)

### Default Groups

In cases where team synchronization is not possible, auto-provisioned users can be assigned one or more default teams.

```ini
alpine.oidc.teams.default=TeamA,TeamB
```

Note that this feature is intended to be used specifically when team synchronization is *disabled*. 
If team synchronization is enabled, memberships will be reset upon next login of the respective user.

### Example setup with Keycloak

The following steps demonstrate how to setup OpenID Connect with Keycloak. Most settings should be applicable to other IdPs as well.

> This guide assumes that:
>
> - the Dependency-Track frontend has been deployed to `https://dependencytrack.example.com`
> - a Keycloak instance is available at `https://auth.example.com`
> - the realm _example_ has been created in Keycloak

1.  Configure the client as shown below:

    ![Keycloak: Configure client](/images/screenshots/oidc-keycloak-client-settings.png)

    - Client ID: `dependency-track`
    - Client Protocol: `openid-connect`
    - Access Type: `public`
    - Standard Flow Enabled: `ON`
    - Valid Redirect URIs: `https://dependencytrack.example.com/static/oidc-callback.html`
      - A trailing wildcard (`*`) was required when using frontend v1.3.0-v4.3.0, in order to support [post-login redirects](https://github.com/DependencyTrack/frontend/pull/47)
      - Starting with v4.4.0, the trailing wildcard is no longer necessary
    - Web Origins: `https://dependencytrack.example.com`

2.  To be able to synchronize team memberships, create a _protocol mapper_ that includes group memberships as `groups` in
    the `/userinfo` endpoint:

   ![Keycloak: Create protocol mapper for groups](/images/screenshots/oidc-keycloak-create-protocol-mapper.png)

        * Mapper Type: `Group Membership`
        * Token Claim Name: `groups`
        * Add to userinfo: `ON` (optional for Dependency-Track v4.3.0 and newer)
        * Add to ID token: `ON` (for Dependency-Track v4.3.0 and newer)

3.  Create some groups, e.g. `DTRACK_ADMINS` and `DTRACK_USERS`:

    ![Keycloak: Groups](/images/screenshots/oidc-keycloak-groups.png)

4.  Verify that all required claims are present in the `/userinfo` endpoint

- Acquire an access token for a user and call `/userinfo` with it
- You can temporarily set _Direct Access Grants Enabled_ to `ON` in the client settings to enable the [Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3)

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

- The response should look similar to this:

```json
{
  "groups": ["DTRACK_USERS"],
  "sub": "290e5d27-25d2-414c-a04c-5d03cd0e1db8",
  "email_verified": true,
  "preferred_username": "demo-user",
  "email": "demo@example.com"
}
```

5. Configure OIDC for both API server and frontend of Dependency-Track, as demonstrated below for a docker-compose deployment:

   ```yaml
   version: "3"

   services:
     dtrack:
       image: dependencytrack/dependency-track
       environment:
         # ...
         - "ALPINE_OIDC_ENABLED=true"
         - "ALPINE_OIDC_CLIENT_ID=dependency-track"
         - "ALPINE_OIDC_ISSUER=https://auth.example.com/auth/realms/example"
         - "ALPINE_OIDC_USERNAME_CLAIM=preferred_username"
         - "ALPINE_OIDC_TEAMS_CLAIM=groups"
         - "ALPINE_OIDC_USER_PROVISIONING=true"
         - "ALPINE_OIDC_TEAM_SYNCHRONIZATION=true"

     dtrack-frontend:
       image: dependencytrack/frontend
       environment:
         # ...
         - "OIDC_ISSUER=https://auth.example.com/auth/realms/example"
         - "OIDC_CLIENT_ID=dependency-track"
   ```

6. Login to Dependency-Track as `admin` and navigate to _Administration -> Access Management -> OpenID Connect Groups_

- Create groups with names equivalent to those in Keycloak (these must match exactly, including case)
- Add teams that the groups should be mapped to

  ![Group mappings](/images/screenshots/oidc-groups.png)

7. Use the _OpenID_ button on the login page to sign in with a Keycloak user that is member of at least one of the configured groups. Navigating to _Administration -> Access Management -> OpenID Connect Users_ should now reveal that the user has been automatically provisioned and team memberships have been synchronized:

   ![OIDC User](/images/screenshots/oidc-user.png)

> Dependency-Track associates every OpenID Connect user with their subject identifier (`sub` claim of the access token) upon first login.
> If a user with the same name but a different subject identifier attempts to log in via OIDC, Dependency-Track will refuse to authenticate that user. This is done to prevent account takeovers, as some identity providers allow users to change their usernames. Also, uniqueness of usernames is not always guaranteed, while the uniqueness of subject identifiers is.

### Example setup with OneLogin

The following steps demonstrate how to setup OpenID Connect with OneLogin.

> This guide assumes that:
>
> - the Dependency-Track frontend has been deployed to `https://dependency-track.example.com`
> - a OneLogin instance is available at `https://example.onelogin.com`

1.  Log in to OneLogin and navigate to _Administration -> Applications -> Add App_
  - Search for _OpenID Connect (OIDC)_

  ![OneLogin OIDC Application](/images/screenshots/onelogin-oidc.png)

2.  In the _Configuration_ section, set the following values:
  - Login Url: `http://dependency-track.example.com/api/v1/user/login`
  - Redirect URI's: `https://dependency-track.example.com/static/oidc-callback.html`

  ![OneLogin OIDC Application Configuration](/images/screenshots/onelogin-oidc-configuration.png)

3.  In the _Parameters_ section, click on the `Groups` _OpenId Connect (OIDC) Field_ and set the following values:
  - Default: `Department (Custom)` (for team synchronization, this must be the field that you use for the user's groups, e.g. Department, Team, Role, etc.)
  - Transform: `Semicolon Delimited Input (Multi-value output)`

  ![OneLogin OIDC Application Parameters](/images/screenshots/onelogin-oidc-parameters.png)
  ![OneLogin OIDC Application Parameters Field Groups](/images/screenshots/onelogin-oidc-parameters-field-groups.png)

4.  In the _SSO_ section, copy the `Client ID` and use it to set the `alpine.oidc.client.id` and `OIDC_CLIENT_ID` configuration values in the API server and frontend respectively

  ![OneLogin OIDC Application SSO](</images/screenshots/onelogin-oidc-sso.png>)

5.  Login to Dependency-Track as an admin and navigate to _Administration -> Access Management -> OpenID Connect Groups_
  - Create groups with names equivalent to those in OneLogin (these must match exactly, including case, with the values of the `Groups` field set in the _Parameters_ section)
  - Add teams that the groups should be mapped to

6.  Use the _OpenID_ button on the login page to sign in with a OneLogin user that is member of at least one of the configured groups. Navigating to _Administration -> Access Management -> OpenID Connect Users_ should now reveal that the user has been automatically provisioned and team memberships have been synchronized

### Azure Active Directory app registration

The following steps demonstrate how to setup OpenID Connect with Azure Active Directory.

> This guide assumes that:
>
> - the Dependency-Track frontend has been deployed to `https://dependencytrack.example.com`
> - an Azure Active Directory tenant has been created

1. Add an app registration for Dependency-Track to your Azure AD tenant:

   - Name: `Dependency-Track`
   - Supported account types: `Accounts in this organizational directory only`
   - Redirect URI (optional): Leave empty for now

2. Under Authentication:
   
   - Add `https://dependencytrack.example.com/static/oidc-callback.html` as a Single Page Application Redirect URI
   - leave all settings at default:

3. Under Token configuration:
   
   - Click Add groups claim
   - Select the group types you'd like to include
     - If you are unsure, start by trying all options
     - If you are in a large organization and have users with lots of groups, you may want to choice only `Groups assigned to the application` to avoid SSO issues. See #2150
 
4. Under API permissions, add the following Microsoft Graph API permissions:
   - OpenId permissions -> email
   - OpenId permissions -> openid
   - OpenId permissions -> profile
   - GroupMember -> GroupMember.Read.All
