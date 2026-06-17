| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-04-17 | [@nscuro](https://github.com/nscuro) |

## Context

Users have long requested the ability to filter notifications based on their content. For example, an organization
may only want to receive notifications for newly discovered vulnerabilities of `CRITICAL` or `HIGH` severity,
or only for components matching a certain name pattern. The existing notification rule model supports filtering
by project and tags, but has no mechanism for filtering by the properties of the notification itself.

One approach would be to add dedicated filter fields to notification rules, such as a severity threshold dropdown
or a component name input. This does not scale. Every new filter would require a schema migration, API changes,
and corresponding UI work. As the number of filterable properties grows, the rule model and UI become increasingly
complex and rigid.

Another approach would be to extend the existing project and tag filters to cover content-level properties. 
This would conflate two fundamentally different concerns. Project and tag filters control which projects a rule applies
to. Content filters control which notifications within those projects are relevant. Mixing the two makes the
filtering logic harder to reason about and harder to extend.

What is needed is a mechanism that is expressive enough to cover arbitrary notification properties, does not
require code changes when new properties are added, and is safe to evaluate in a high-throughput notification
pipeline.

## Decision

We will allow users to attach a [CEL] (Common Expression Language) filter expression to notification rules.
When a notification matches a rule, the filter expression is evaluated against the notification.
If it evaluates to `true`, the notification is dispatched. If it evaluates to `false`, it is suppressed.

CEL is a natural fit for this use case. Dependency-Track's notifications are defined as [Protocol Buffer] messages,
and CEL has native support for Protobuf types. This means that all fields of a notification and its subject are
automatically available in expressions without any additional mapping or configuration. When new fields are added
to the notification schema, they become available in filter expressions immediately. CEL is already used in the
project for vulnerability policies, so it is a known quantity in terms of integration and operational behavior.
The language is designed to be fast, safe (no side effects, no I/O, no unbounded loops), and well-specified.

The following variables are available in filter expressions:

- `level`, `scope`, `group` for the notification's level, scope, and group (as integer enum values, with named constants like `Level.LEVEL_INFORMATIONAL`)
- `title` and `content` for the notification's title and content strings
- `timestamp` for the notification's timestamp
- `subject` for the notification's subject, typed according to the notification group (e.g. `NewVulnerabilitySubject` for `GROUP_NEW_VULNERABILITY`)

Example expressions:

- `subject.vulnerability.severity == "CRITICAL"` to only receive critical vulnerabilities.
- `subject.project.name.startsWith("acme-")` to filter by project name prefix.
- `"CRITICAL" in subject.overview.new_vulnerabilities_count_by_severity` to filter scheduled vulnerability summaries.

Filter expressions are optional. Rules without a filter expression behave exactly as before, preserving full
backward compatibility.

Expressions are validated at save time. When a user creates or updates a notification rule with a filter
expression, the expression is compiled and checked against the CEL type environment. If the expression is
invalid, the API returns an [RFC 9457] problem details response with precise error locations (line, column,
message). This fail-fast approach prevents users from saving expressions that would never evaluate successfully.

At dispatch time, if a filter expression fails to evaluate due to a runtime error, the rule matches the
notification. This fail-open strategy ensures that a misconfigured expression causes over-notification rather
than silent suppression. For a security system, failing to deliver a notification is worse than delivering
one too many.

Project and tag filtering is applied before filter expression evaluation. This ordering ensures that the cheaper
filter is executed first, and that project-level access restrictions are enforced regardless of what the
expression says.

Compiled CEL programs are cached in memory (up to 256 entries with a TTL of one hour) to avoid repeated compilation
of the same expression across notification dispatches. The cache is keyed by expression text, so updating an
expression naturally invalidates the previous cache entry.

## Consequences

Users can now filter notifications by any property of the notification or its subject without requiring code
changes, schema migrations, or UI updates. This covers the use cases described in
[DependencyTrack/dependency-track#3767](https://github.com/DependencyTrack/dependency-track/issues/3767)
and similar requests.

Filter expressions are a power-user feature. Users need to understand CEL syntax and the structure of
notification Protobuf messages to write effective expressions. Documentation and example expressions will be
important for adoption.

The fail-open strategy means that broken expressions will not silently suppress notifications. Operators will
see warnings in logs when expressions fail to evaluate, giving them the opportunity to fix the expression
without missing notifications in the meantime.

The expression length is capped at 2048 characters to prevent abuse, which is sufficient for any reasonable
filter condition.

[CEL]: https://cel.dev
[Protocol Buffer]: https://protobuf.dev
[RFC 9457]: https://www.rfc-editor.org/rfc/rfc9457