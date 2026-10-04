| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-09-11 | [@nscuro](https://github.com/nscuro) |

## Context

[ADR 040] added service accounts. Their only credential is an API key, a static secret that someone has to create,
store in the CI system, and delete when it leaks. Since [ADR 041], someone also has to rotate it before it expires.

Most platforms that run CI jobs and other workloads give each job a short-lived identity token, signed with a key
the platform publishes. GitHub Actions and GitLab CI issue OpenID Connect (OIDC) ID tokens.
SPIRE, the reference implementation of SPIFFE, issues JWT-SVIDs, which are JSON Web Tokens (JWTs) that carry a SPIFFE ID.
Workload identity federation (WIF), [requested in #7056][gh-issue-7056], lets a workload authenticate
to Dependency-Track with that token, so the workload stores no Dependency-Track secret.

OIDC login and LDAP live in deployment configuration, because each exists once per deployment.
WIF needs one trust configuration per cluster or CI platform, and a binding per pipeline.
Bindings reference service accounts, which only exist in the database.

### Possible Solutions

#### A: Verify platform tokens on every request

Accept a platform token as the bearer token on every API request, and verify it each time.

*Pro*:

1. No exchange step and no session rows.

*Con*:

1. Every request pays for signature verification and a key lookup.
2. It breaks the `bearerAuth` scheme of API v2, which promises an opaque token issued by the server.

#### B: Exchange, with trust configuration in deployment configuration

Configure providers as properties or environment variables, like OIDC login. A token endpoint creates a session.

*Pro*:

1. Follows the OIDC and LDAP configuration model, and the tooling that manages the deployment also manages providers.

*Con*:

1. No reload. Adding a cluster means restarting every node.
2. Bindings still live in the database, and cannot reference a provider with a foreign key.

#### C: Exchange, with providers and bindings as runtime configuration

Store providers and bindings in the database, and manage them through API v2.
A token endpoint verifies the platform token once and creates an ordinary session.

*Pro*:

1. Changes take effect without a restart.
2. Bindings reference providers and service accounts with foreign keys. Deleting either removes the binding.

*Con*:

1. New REST API resources, new tables, and an endpoint that anyone can call without authentication.

## Decision

We will follow solution **C**.

### Overview

An administrator creates a *provider*, which says which issuer to trust, where its keys are, and which audience
tokens must carry. They then create *bindings*, which map a subject of that provider to a service account.
A workload posts its platform token to the token endpoint, names the provider and the service account it wants to act as,
and receives a session for that service account when one of its bindings matches.

### Providers and bindings

A provider has a unique name, a type, an issuer, a key source, an audience, and a session lifetime.
The lifetime defaults to 1 hour, and cannot exceed 24 hours. One issuer may be registered more than once,
for example with two audiences or two session lifetimes. Everything but the name and type can change,
because bindings reference the provider by name, and an issuer that moves, such as a recreated cluster,
should not invalidate every binding.
SPIFFE providers are the exception, because their bindings carry the trust domain in the subject,
so they stop matching when the trust domain changes.

A binding maps a subject and an optional condition to one service account. A binding cannot point to a human user.
It has no session lifetime of its own. The token of a client matches several bindings when they overlap,
and the lifetime would then depend on which binding the server picks. The server cannot know which one the admin meant,
because a narrower binding is not always meant to be stricter. Two pipelines behind the same issuer that act
as accounts of different risk use two providers for that issuer, each with its own lifetime.
Managing providers and bindings requires access management permissions.

A subject is an exact value, or a non-empty prefix followed by `*`. The prefix must end with `:` or `/`,
because loose prefixes like `repo:acme/app*` also match `repo:acme/app-evil:...`.
GitHub Actions, GitLab CI, CircleCI, and Kubernetes all separate organizations, projects, and namespaces in
`sub` with one of the two delimiters. For SPIFFE providers, the subject must lie in the provider's trust domain,
and a prefix must end with `/`, as in [SPIFFE client authentication][spiffe-client-auth].

The server accepts duplicate and overlapping bindings. Whether two conditions overlap cannot be decided in general,
and comparing their text could fail on whitespace. Overlaps do no harm, because the client names the service account,
and the server only evaluates that account's bindings until one matches. The session is the same whichever binding
matches. It tries bindings from oldest to newest,
so the audit log names the same binding for the same token.

### Provider types

**OIDC** covers CI systems, cloud platforms, Kubernetes, and other OIDC issuers.
Tokens must carry an `iss` claim equal to the issuer.

**SPIFFE** covers deployments that run SPIRE or another SPIFFE implementation.
It cannot be an OIDC provider, for the following reasons:

1. The [JWT-SVID specification][spiffe-jwt-svid] does not require `iss`.
   The SPIFFE ID in `sub` carries the trust domain instead.
2. A SPIFFE bundle endpoint serves a key set directly. There is no discovery document.
3. Keys in a [SPIFFE bundle][spiffe-bundle] are marked for `jwt-svid` use, not `sig`. A standard key lookup skips them.

For SPIFFE, the issuer field holds the trust domain, such as `example.org`.
The server ignores `iss` and requires `sub` to start with `spiffe://example.org/`.
It rejects an issuer that is not a bare trust domain, such as `spiffe://example.org`.

Both types only accept the asymmetric signature algorithms that the JWT-SVID specification allows.
Tokens must carry `exp` and `sub`, and the provider's audience in `aud`.

### Key sources

A provider gets its keys in one of two ways:

* **From a URL.** For OIDC, the server reads the [discovery document][oidc-discovery] of the issuer when the provider is saved,
  checks that its issuer matches, and stores the key set URL it names. A key set URL given directly skips discovery.
  For SPIFFE, the URL is the bundle endpoint. The server only supports endpoints with public web
  certificates, which is the `https_web` profile of [SPIFFE federation][spiffe-federation].
  The server does not record whether a key set URL came from discovery. When the issuer of an OIDC provider changes
  and the request names no key source, the server runs discovery again and replaces the URL.
* **Inline.** The provider stores the key set, and the server fetches nothing. The server rejects private and symmetric keys.

Inline key sets serve issuers the server cannot reach, mainly self-managed Kubernetes. A kubeadm cluster
[uses an in-cluster issuer][kubeadm-issuer] with [a self-signed CA][k8s-certs],
and [lets only service accounts read its discovery document][p-k8s].

### Binding conditions

A condition is a [CEL] (Common Expression Language) expression. It sees the claims of the verified token
as the `claims` map, and must return a boolean.

Policies and notification filters already use CEL, see [ADR 017]. [Kubernetes][k8s-authn-config] uses CEL
over token claims for the same purpose. A map of exact claim values would be simpler, but cannot express lists,
prefixes, or nested claims. Platforms do not put everything into `sub`. [GitLab CI][p-gitlab], for example,
keeps the environment in a separate claim.

The subject stays required even with a condition. GitHub, GitLab.com, and CircleCI issue tokens with any audience
to anyone with an account. The audience isolates nothing there, so the subject has to name the organization.
[Google Cloud][gcp-wif-pipelines] requires the same for such issuers.

The server compiles and type-checks a condition when the binding is saved. At exchange time,
a condition that fails to evaluate, for example on a missing claim, does not match.

Conditions only see claims of verified tokens, and only administrators write them.
So, as with policies and notification filters, there are no evaluation limits.
We will add caps once an expensive expression slows exchanges down.

### Token exchange

Workloads exchange their platform token at `POST /api/v2/oauth/token`, with the token exchange grant of [RFC 8693].
The path is not specific to workload identity, so a later login of users with an OIDC ID token can use the same endpoint.

The endpoint follows the token endpoint rules of [RFC 6749], so OAuth 2.0 clients need no custom code.
That includes the response codes and the error format of RFC 6749, where our API guidelines ask for
`201` and problem details.

We chose RFC 8693 over the JWT bearer grant of [RFC 7523], because RFC 7523 requires an `iss` claim that JWT-SVIDs may omit.
RFC 8693 leaves the validity criteria of the subject token to the server.
[OpenAI][OpenAI WIF] uses it for the same purpose, while [Anthropic][anthropic-wif-reference] uses RFC 7523.

Beyond the parameters of RFC 8693, the client names the provider and the service account.
The server never guesses either from the token. Guessing the provider from `iss` fails
for SPIFFE tokens without `iss`, and for an issuer registered twice. Guessing the service account from the bindings
is ambiguous when bindings of several accounts match. [OpenAI][OpenAI WIF] also makes the client name both.
[Anthropic][anthropic-wif-reference] makes it name the matching rule and the service account.

A refused subject token returns `invalid_request`, as RFC 8693 requires,
and the response does not say which check failed. When the provider's keys cannot be fetched,
the endpoint returns `503` with problem details instead. The token may well be valid,
and a client that reads `invalid_request` stops retrying.

The access token is the session's opaque token, the same kind the login endpoints issue, and fits the RFC 6749
definition of an access token. It carries all permissions of the service account. The endpoint has no `scope` parameter,
which RFC 6749 allows when the server documents its default. The server refuses the exchange when the service account is suspended.

The session lasts for the provider's session lifetime, regardless of when the subject token expires.
[GitLab CI][p-gitlab] and [SPIRE][spire-server-config] issue tokens that expire after 5 minutes by default,
and a CI job that uploads a BOM and waits for its analysis takes longer than that.
The subject token proves the workload's identity at the time of the exchange.

### Replay protection

The server does not remember exchanged tokens, so a token can be exchanged again until it expires.
[RFC 8693] does not require replay protection. A `jti` check would not work on every platform.
[CircleCI][p-circleci] tokens have no `jti`, and [Entra ID][p-entra-claims], which issues the tokens of
Azure managed identities, uses its own `uti` claim instead. [The kubelet][kubelet-token-cache]
caches the token of a pod, so a restarted container reads the same token again.

### Outbound fetches

The server fetches remote documents when a provider is saved, and at exchange time when keys are missing from the cache.
An unauthenticated caller can trigger the second kind with a token that carries an unknown key ID.
Providers with an inline key set cause no fetches. For all others:

* The server only allows `https` URLs without user information.
* After DNS resolution, the server rejects loopback, link-local, multicast, and wildcard addresses.
  That covers the metadata endpoint at `169.254.169.254`, but not all of them. AWS serves another at `fd00:ec2::254`,
  which is a private address. Metadata endpoints only speak `http`, so the `https` rule is what blocks them.
  A name can resolve to a different address between the check and the fetch. We accept that gap for now.
* When a configured HTTP proxy handles the destination, the server skips the address check. The proxy resolves
  the name, so a local lookup says nothing about where the request goes, and fails where only the proxy has DNS.
* A fetch must complete within 10 seconds, response body included.
* The server does not follow redirects, which could lead to an address it never checked.
* Private address ranges stay allowed, because internal issuers and on-premises SPIFFE bundle endpoints
  are a main use case. The administrator of a self-hosted instance already controls its network.
* Fetched bodies never appear in responses or logs.
* The server caches key sets and limits how often it fetches them for each provider. When a refresh fails,
  it keeps using the last fetched key set for a limited time, so that a short outage of the issuer does not fail every exchange.

Saving a key set URL fails when the key set cannot be fetched.
The exchange loads the provider from the database every time, so changes take effect on every node at once.

### Audit logging

The server logs exchanges, refused exchanges, and changes to providers and bindings as security events.
An exchange logs the binding that matched, and the token's `jti` if it has one, to tie a session to the subject token.
When it refuses a token that passed verification, it also logs the token's claims, so administrators can see why
no binding matched. It never logs subject tokens.

### Out of scope

* SPIFFE bundle endpoints that authenticate with SPIFFE certificates, the `https_spiffe` profile.
* Rate limiting of the token endpoint. The login endpoints have none either.
* Client authentication with signed JWTs, `private_key_jwt`.
* `WWW-Authenticate` challenges on `401` responses, which [RFC 6750] requires.
  No authentication method of Dependency-Track sends them today.

## Consequences

* A CI job authenticates without a stored secret. Suspending the service account or deleting the binding cuts it off.
* A subject token can be exchanged any number of times until it expires,
  which takes up to 24 hours for [Azure managed identities][p-azure-mi].
  Whoever holds one can use it like a credential until then. Retries and restarted containers need no special handling.
* A session outlives the subject token it was created from. By default, a JWT-SVID that expires after 5 minutes
  is exchanged for a session of 1 hour.
* Administrators need to know CEL and the claim names of their platform. A condition is part of the security boundary.
  One that matches more tokens than intended lets more workloads act as the service account.
* Platforms change their token formats, and bindings written for the old format stop matching.
  [GitHub uses a new default `sub` format for repositories created after 2026-07-15][p-github].
* Deleting a binding or a provider does not end sessions already created, which last at most 24 hours.
  Suspending the service account ends them at once.
* When an issuer with an inline key set rotates its keys, exchanges fail until an administrator stores the new set.
* While an issuer is unreachable, the server trusts keys the issuer may have retired for a limited time.
* A `503` tells the caller that the provider exists and fetches its keys from a URL.
* Anyone can make the server verify a token, and contact a configured issuer within the fetch limit.
  Callers cannot choose the URL.
* Behind an HTTP proxy, the proxy decides which addresses the server can reach.
* An administrator can point a provider at an internal service. The server only accepts a valid key set and never shows the body,
  so the administrator learns whether the fetch worked, and nothing more. The access management permissions already grant more than that.

[ADR 017]: ./017-notification-filter-expressions.md
[ADR 040]: ./040-service-accounts.md
[ADR 041]: ./041-api-key-expiry.md
[CEL]: https://cel.dev/
[OpenAI WIF]: https://developers.openai.com/api/reference/workload-identity-federation
[RFC 6749]: https://www.rfc-editor.org/rfc/rfc6749
[RFC 6750]: https://www.rfc-editor.org/rfc/rfc6750
[RFC 7523]: https://www.rfc-editor.org/rfc/rfc7523
[RFC 8693]: https://www.rfc-editor.org/rfc/rfc8693
[anthropic-wif-reference]: https://platform.claude.com/docs/en/manage-claude/wif-reference
[gcp-wif-pipelines]: https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines
[gh-issue-7056]: https://github.com/DependencyTrack/dependency-track/issues/7056
[k8s-authn-config]: https://kubernetes.io/docs/reference/config-api/apiserver-config.v1/#apiserver-config-k8s-io-v1-AuthenticationConfiguration
[k8s-certs]: https://kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/
[kubeadm-issuer]: https://github.com/kubernetes/kubernetes/blob/v1.34.0/cmd/kubeadm/app/phases/controlplane/manifests.go
[kubelet-token-cache]: https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/kubelet/token/token_manager.go
[oidc-discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[p-azure-mi]: https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity
[p-circleci]: https://circleci.com/docs/guides/permissions-authentication/openid-connect-tokens/
[p-entra-claims]: https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
[p-github]: https://docs.github.com/en/actions/reference/security/oidc
[p-gitlab]: https://docs.gitlab.com/ci/secrets/id_token_authentication/
[p-k8s]: https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
[spiffe-bundle]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md
[spiffe-client-auth]: https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/
[spiffe-federation]: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md
[spiffe-jwt-svid]: https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md
[spire-server-config]: https://spiffe.io/docs/latest/deploying/spire_server/
