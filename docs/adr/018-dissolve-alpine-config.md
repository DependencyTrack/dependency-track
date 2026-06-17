| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-04-25 | [@nscuro](https://github.com/nscuro) |

## Context

The codebase carries two parallel configuration APIs.

The legacy one is inherited from the Alpine framework. Properties are declared as Java enum
constants, with their default values hardcoded into the enum constructor. Access goes through a
singleton facade. It's already deprecated.

The modern one is MicroProfile / SmallRye Config. Properties are plain strings, defaults live in
`application.properties`, and SmallRye provides standard mechanisms for profiles, expressions,
secret handling, and config sources.

The legacy facade is by now a thin wrapper that delegates to the modern API, but a large number of
call sites still go through it, including some in static field initializers. New modules read
config directly through MicroProfile, while older code uses the singleton. There is no single,
idiomatic way to access configuration.

This has practical costs:

* Enum-based property declarations duplicate what `application.properties` already does, and
  prevent operators from overriding defaults through standard MicroProfile mechanisms without code
  changes.
* Docker secret support is a one-off method that reads a sibling `*.file` property. SmallRye
  ships a native [`SecretKeysHandler`](https://smallrye.io/smallrye-config/Main/config/secret-keys/)
  SPI for this, but the bespoke implementation blocks adoption.
* The facade hides behavior. Numeric parse errors are swallowed and replaced by `-1`. List
  parsing reimplements trimming that SmallRye already does.

[`@ConfigMapping`](https://smallrye.io/smallrye-config/Main/config/mappings/) was considered as
the migration target and rejected. In a non-CDI environment every mapping must be manually
registered, which is more ceremony than the existing wrappers. It also validates eagerly, so
conditional configs (e.g. an LDAP URL that is only required when LDAP is enabled) can only be
expressed by making every property optional and reimplementing the conditional logic in code.

## Decision

We will dissolve the legacy configuration API and migrate all consumers to MicroProfile / SmallRye
Config directly.

Property keys move from enum constants to plain string constants. Default values move out of Java
code and into properties files, layered by config source ordinal so that modules can ship sensible
defaults and the apiserver can override them where the runtime diverges.

Docker secret support is rebuilt on top of SmallRye's `SecretKeysHandler` SPI, exposing a
`${file::/path}` expression syntax for any property. The legacy `*.file` convention is removed
outright, and the apiserver refuses to start if any of the previously supported keys are still
set, so the migration cannot fail silently.

Behavior on the legacy facade that is not strictly configuration access (data directory resolution,
build-info accessors, system identity) moves to dedicated utilities or to direct config reads at
the call site. The facade itself is then deleted.

## Consequences

Configuration access becomes uniform: one API, one defaulting mechanism, one secrets mechanism.
Adding a new property is one string constant and one default. SmallRye's profile, expression, and
secret-handler features become first-class for every property. The long-term goal of removing the
alpine module also moves forward, since the legacy config API was one of its most deeply embedded
types.

There are notable behavioral changes:

* Misconfigured numeric properties now fail fast at startup, where the legacy facade used to log
  and substitute `-1`.
* Operators must rewrite legacy `*.file` Docker-secret settings as `${file::}` expressions. A
  transparent fallback was prototyped and rejected. The necessary interceptor chain ordering is
  brittle, and a regression would silently break LDAP, proxy, or database authentication. Failing
  fast surfaces the migration loudly instead.
