| Status   | Date       | Author(s)                              |
|:---------|:-----------|:---------------------------------------|
| Proposed | 2026-08-28 | [@jjj-n](https://github.com/jjj-n)     |

## Context

Dependency-Track supports local, LDAP, and OpenID Connect (OIDC) login. The frontend starts
the OIDC flow and sends the resulting tokens to the API server. The API server then creates a
Dependency-Track session. This works when Dependency-Track is the OIDC client.

Some deployments put [OAuth2 Proxy] in front of every application. The gateway authenticates
the browser before a request reaches an application. It can pass the authenticated user, email,
and groups to the upstream application in HTTP headers. Repeating the OIDC flow in the
Dependency-Track frontend gives the user a second login step. It also requires a separate OIDC
client registration and direct access from Dependency-Track to the identity provider.

Headers from an authentication proxy are security assertions. They are not signed. A client can
forge them when it can reach the API server without the gateway, or when the gateway preserves
headers supplied by the client. Proxy authentication therefore needs an explicit trust boundary.

Dependency-Track authorization is based on persistent users, teams, and permissions. Its
frontend and REST API use a Dependency-Track bearer session after login. API keys must continue
to work for automated clients.

### Possible Solutions

#### Exchange trusted proxy headers for a Dependency-Track session

The frontend can call a session exchange endpoint when it has no Dependency-Track session. The
endpoint can use identity headers added by OAuth2 Proxy. It can create or find a local proxy user
and return a normal Dependency-Track session.

This option works with every identity provider supported by OAuth2 Proxy. It also keeps the
existing authorization and session model. However, the API server must trust the gateway and the
deployment must prevent direct access to the API server.

#### Validate a token forwarded by OAuth2 Proxy

OAuth2 Proxy can forward an access token or OIDC ID token. Dependency-Track can validate that
token with its existing OIDC support before it creates a session.

This option does not trust plain identity headers. However, it only works for providers and
tokens that Dependency-Track can validate through OIDC. It may require another client
registration, access to the identity provider, and provider-specific claim configuration. It
does not solve the general proxy authentication use case.

#### Authenticate every API request from proxy headers

The API server can treat proxy headers as credentials on every request. This avoids a session
exchange.

This option conflicts with the frontend's current session flow. It also mixes proxy identity,
API keys, and session bearer tokens in the common authentication filter. Logout and direct API
access become harder to define.

## Decision

We will exchange trusted OAuth2 Proxy identity headers for a normal Dependency-Track session.
The integration will be disabled by default.

The API server will extend the existing version 1 login API with a session exchange endpoint.
This is an extension of the existing login contract, not a new authentication method for every
REST endpoint. The endpoint will have these properties:

* It will only accept identity when proxy authentication is enabled.
* It will read the user and email values from configurable header names. The defaults will
  match the `X-Forwarded-*` request headers emitted by OAuth2 Proxy.
* It will reject a request when the user header is missing or empty.
* It will create or find a persistent proxy user. A username that already belongs to another
  user type will be rejected.
* It will issue the same short-lived bearer session used by other login methods. Later API
  requests will use that session and the existing authorization filters.
* It will not accept passwords, access tokens, or ID tokens from the browser.

Proxy users will be a distinct user type in the shared user model. This keeps their origin clear
and avoids treating an unverified proxy assertion as an OIDC identity. Proxy users will use the
existing team and permission model. User provisioning will be opt-in. Operators can assign
default teams to newly provisioned users. Administrators can change team membership through the
existing access management API. Dynamic group synchronization is outside the first version.

The frontend will attempt the proxy session exchange before it displays the login choices. A
successful exchange will run the existing permission check and open the requested page. When
proxy authentication is disabled, the frontend will continue with the current local, LDAP, or
OIDC login flow.

The deployment is part of the trust boundary. Operators must configure the gateway to replace
the selected identity headers, not preserve values sent by clients. They must also prevent
clients from reaching the API server without the gateway. The configuration documentation will
include examples for direct upstream mode and NGINX `auth_request` mode.

## Consequences

* Users authenticated by OAuth2 Proxy can open the dashboard without a second login action.
* OAuth2 Proxy can use OIDC or another provider. Dependency-Track does not need to validate or
  store the provider's token.
* Existing API key clients and Dependency-Track sessions keep their current behavior.
* The API server still controls authorization through users, teams, and permissions.
* A new persistent user discriminator and a database migration are required.
* The API server and frontend changes must be released together for seamless login. Older
  frontends will continue to show the normal login page.
* A bad gateway configuration can allow identity spoofing. Enabling this feature asserts that
  the gateway headers and the network path to the API server are trusted.
* Logging out of Dependency-Track only deletes the local session. The OAuth2 Proxy session may
  create a new local session when the login page loads again. A gateway-wide logout flow is
  outside the scope of this decision.

[OAuth2 Proxy]: https://oauth2-proxy.github.io/oauth2-proxy/
