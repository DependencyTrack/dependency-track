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

[matrix-capabilities]: https://spec.matrix.org/v1.11/client-server-api/#capabilities-negotiation
