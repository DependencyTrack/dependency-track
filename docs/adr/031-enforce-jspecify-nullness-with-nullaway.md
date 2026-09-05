| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-07-14 | [@nscuro](https://github.com/nscuro) |

## Context

Most modules use [JSpecify] annotations. Packages are marked with `@NullMarked`,
and nullable values are annotated with `@Nullable`. The annotations are informal today.
Nothing checks them, so wrong or missing annotations and actual `null`-safety bugs go unnoticed.

Spring Framework, Caffeine, Micrometer, OpenTelemetry and others enforce the same annotations
at compile time with [NullAway], a null checker that runs as an [Error Prone] plugin
(see corresponding posts on the [Spring blog] and [Uber blog]).

## Decision

We will enforce JSpecify nullness semantics at compile time with NullAway.

Error Prone serves only as the host for NullAway. All other Error Prone checks stay disabled.

Only code inside `@NullMarked` scopes is checked, and generated sources are excluded.

Test sources are not checked. Error Prone is disabled for the `default-testCompile` compiler execution.
Checking them surfaced no defects, but required loads of `@SuppressWarnings("NullAway")` across many classes,
mostly on tests that pass `null` deliberately to assert the code under test rejects it.
It added noise and increased compilation times for no conceivable benefit.

Enforcement is on by default for every module, so new modules cannot forget to enable it.

Modules with pre-existing violations, such as `dex`, can opt out by setting the `nullaway.severity`
property to `OFF` in their `pom.xml` until they are cleaned up.

## Consequences

Nullness violations in `@NullMarked` scopes of opted-in modules fail the build.

Compilation becomes slower because Error Prone runs in every module.
A clean `test-compile` of all modules without build caching takes ~15% longer
(measured as going from 15.2s to 17.5s median across five runs).

Modules that are not yet opted in gain no safety until they are migrated.

Packages without a `@NullMarked` `package-info.java` are silently unchecked.
Omitting the annotation is thus an implicit opt-out. This is accepted as it avoids
extensive code churn on legacy code for now.

[Error Prone]: https://errorprone.info/
[JSpecify]: https://jspecify.dev/
[NullAway]: https://github.com/uber/NullAway
[Spring blog]: https://spring.io/blog/2025/03/10/null-safety-in-spring-apps-with-jspecify-and-null-away/
[Uber blog]: https://www.uber.com/en/blog/nullaway/
