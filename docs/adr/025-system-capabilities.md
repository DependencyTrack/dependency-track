| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Proposed | 2026-05-20 | [@nscuro](https://github.com/nscuro) |

## Context

The unauthenticated `/version` endpoint previously aggregated information about the active database
product, its version, and the configured secret manager backend. Most of that detail was not useful
to clients, and we narrowed the endpoint to product version information by removing the contributing
`AboutProvider` extension points.

The user interface needs to know which server features are enabled and whether they are restricted,
so that controls can be hidden or disabled instead of failing at submit-time. For example, the
secret manager may be configured as read-only, in which case the UI should disable mutating controls.

## Decision

Introduce `GET /api/v2/internal/system-capabilities`. Authentication is required. No permission is required.
The endpoint starts under `/internal` so the contract can evolve before we commit to stability.
It may be promoted to the top-level path once the shape has settled and external use-cases are known.

The response is a map of namespaces to capability objects. Each namespace is owned by one subsystem
and contains only behavioural flags. The contract is additive, such that clients tolerate unknown
namespaces and unknown flags. An absent namespace or flag means the feature is enabled and permissive.

Flag names must be chosen so that the restrictive state is the truthy value, and the permissive
state is the default. For example, authors should prefer `read_only` over `writable`,
and `requires_approval` over `auto_approves`. This keeps the "absent equals permissive"
rule consistent across all namespaces.

```json
{
  "capabilities": {
    "secret_management": {
       "read_only": false
    }
  }
}
```

The shape and contract are modeled on [Matrix `GET /_matrix/client/v3/capabilities`][matrix-capabilities],
which solves the same problem for chat clients. 

Subsystems contribute through a service provider interface. Namespace collisions fail fast at boot.
A provider that throws at request time has its namespace omitted rather than failing the request.

## Consequences

Adding a capability is a single-file change owned by the contributing subsystem.
No endpoint or schema change is required.

Frontends must tolerate unknown keys. The server can extend without coordinated releases.

Pre-login hints, such as which authentication methods are enabled, are not supported until a public
sibling endpoint is added. Until then, clients must authenticate before reading any capability.


## Follow-up (2026-11-12)

The login page needs to know which login methods the server offers before anyone has authenticated.
We add the public sibling endpoint that the consequences above anticipated: `GET /api/v2/internal/system-capabilities/public`.
It requires no authentication, and has the same response shape as the authenticated endpoint.

A provider opts in to the public endpoint by overriding `CapabilityProvider#isPublic()`, which defaults to `false`.
The public endpoint returns only public namespaces. The authenticated endpoint keeps returning all namespaces,
including the public ones, so that clients need a single request after login. Both endpoints share one set of
providers, so namespace collisions between public and non-public providers still fail at boot.

Public capabilities are visible to anyone who can reach the server. A namespace should only be public when clients
need it before login, and when its flags reveal nothing that helps an attacker, such as versions, host names,
or other configuration details.

The first public namespace is `oidc`, with a single flag `disabled`. It mirrors `GET /api/v1/oidc/available`,
which stays in place for existing clients of REST API v1.

Login methods are disabled by default, which sits uneasily with the rule that an absent namespace means enabled.
Providers of such features must therefore always report their state explicitly, rather than omitting the namespace
when the feature is off. A provider that fails at request time is still omitted, so a client may offer a login method
that then fails. We accept this, because the login itself does not depend on the hint.

[matrix-capabilities]: https://spec.matrix.org/v1.11/client-server-api/#capabilities-negotiation
