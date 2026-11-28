# Testing

See [`DEVELOPING.md`](../DEVELOPING.md#testing) for how to run tests.

## What to Test

* A test earns its place when it guards behavior that users or callers rely on,
  and a plausible future change could break it without anyone noticing.
* Don't write change detectors: tests that pin a detail nobody relies on,
  so that every failure ends in updating the test.
  This includes asserting which log message or constant gets used,
  and anything the compiler or NullAway already enforce.
* Test at the outermost layer that is still fast and deterministic.
  It covers wiring, serialization, and authorization that isolated tests skip, and survives refactoring below it.
* Drop to a lower layer only for what the top can't reach, such as error paths, boundaries, and concurrency.
* Don't duplicate coverage a higher-layer test already has. Extend that test instead.
* Unit-test pure functions with wide input spaces, like parsers, converters, and comparators. Parameterize them.
* For a bug fix, start with a test that reproduces the bug.
* A test that would still pass with the change reverted doesn't test the change.

## Structure

* Name test methods `shouldX`, e.g. `shouldThrowWhenConfigIsInvalid`, when the subject is obvious.
  When a test class covers several subjects, as resource tests do, prefix the name with the subject,
  e.g. `updateServiceAccountShouldReturnNotFoundWhenUnknown`.
* A test reads top to bottom without jumping to another method. Duplication between tests is fine, indirection is not.
  * Inline anything that varies per test. `@BeforeEach` is for setup that is identical across the class.
  * Never hide an assertion behind a method that reads like an accessor.
  * Set up only what the test depends on.
  * A helper earns its place by removing real work, not by renaming a few lines.

## Assertions

* Use AssertJ's `assertThat`. Don't use JUnit's `assertEquals`, `assertTrue`, etc.
* Use `assertThatExceptionOfType` instead of `assertThatThrownBy`.
* Assert JSON with json-unit's `assertThatJson` and a text block annotated with `/* language=JSON */`:

```java
assertThatJson(responseJson).isEqualTo(/* language=JSON */ """
    {
      "name": "acme-app"
    }
    """);
```

## Async Code

Async tests must be deterministic, even on a busy CI runner. Prefer, in this order:

1. Drive the loop from the test. Expose a package-private method that runs one iteration,
   instead of starting the background thread.
2. Inject `java.time.Clock` instead of calling `Instant.now()` in the code under test.
   The public constructor defaults to `Clock.systemUTC()`, a package-private one accepts the clock.
3. Use a `CountDownLatch` for handoff, and assert the result of `await`:
   `assertThat(started.await(5, TimeUnit.SECONDS)).isTrue()`. A bare `await` passes silently on timeout.
4. Use Awaitility only for state you can't observe directly, like database rows, metrics, or other threads.

Don't use `Thread.sleep` to wait. It's only acceptable for parking a thread inside a stub on purpose.

When using Awaitility:

* Name the condition: `await("Workflow run to complete")`.
* Bound it with `atMost`: 5 seconds, or up to 30 seconds with a real database or container.
* Prefer `untilAsserted(() -> assertThat(...))` over `until(...)`. It reports the actual value on timeout.
* Use `failFast(...)` when a wrong terminal state is detectable.
* Use `during(...)` with `atMost(...)` to assert that something does *not* happen.
* Use `ignoreException(...)` for lookups that throw until the resource exists.

## Test Doubles

* Prefer real implementations and in-memory variants over mocks.
  Needing a mock is often a sign that the code under test is hard to test. Consider changing the code first.
* Use WireMock for HTTP boundaries, and Testcontainers for PostgreSQL and other infrastructure,
  instead of mocking the client.

## Architecture Rules

* Architecture rules are [ArchUnit](https://www.archunit.org/) tests in `apiserver` named `*ArchitectureTest`.
  `make test-architecture` runs them.
* Write a rule when a constraint is structural, such as which classes may call, extend, annotate,
  or depend on what, and a violation could pass review unnoticed.
  Security boundaries like outbound HTTP are the typical case.
* Prefer a rule over a line in [`AGENTS.md`](../AGENTS.md) or [`DEVELOPING.md`](../DEVELOPING.md).
  A rule fails the build, prose only helps when someone reads it.
* Explain the rule in `.because(...)`. The failure message is the only documentation a violator sees.
* A rule that analyzes `packages = "org.dependencytrack"` must see other modules' classes, too.
  Keep `DoNotIncludeJars` out of its `importOptions`: Maven resolves sibling modules as jars in the `verify` phase,
  so with it, rules would skip every module but `apiserver` in `make test` and CI.
* For a constraint the code already violates, wrap the rule in `FreezingArchRule.freeze(...)`.
  It records existing violations under [`apiserver/src/test/resources/archunit_store`](../apiserver/src/test/resources/archunit_store)
  and fails only on new ones.
  [`archunit.properties`](../apiserver/src/test/resources/archunit.properties) locks the store,
  so adding a frozen rule, or fixing one of its recorded violations,
  fails until you run `make test-architecture UPDATE_STORE=1` once and commit the store changes.
  The store keys rules by description, so changing a frozen rule's description, `.because(...)` included,
  also needs that run, plus removing the old entry from `stored.rules` and its violation file.
