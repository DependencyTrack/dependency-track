# AGENTS.md

## Commands

Use the `make` commands outlined below.
Always set the `AGENT` variable when running make, e.g. `make build AGENT=1`.
Do not invoke Maven directly unless no equivalent `make` target exists.
If Maven needs to be invoked directly, only do so from the repository root.

* Build: `make build`
* Run all tests (slow): `make test`
* Run individual test: `make test-single MODULE=apiserver TEST=FooTest`
* Run individual test methods: `make test-single MODULE=apiserver TEST=FooTest#test`
* Run multiple tests: `make test-single MODULE=apiserver TEST="FooTest,BarTest"`
* Clean: `make clean`
* Clean build cache: `make clean-build-cache`
* Run e2e tests: `make test-e2e`
* Lint (Java): `make lint-java`
* Format (Java): `make format-java`
* Lint (OpenAPI): `make lint-openapi`
* Lint (Protobuf): `make lint-proto`
* Lint (Flyway migrations): `make lint-migrations`

> [!NOTE]
> When running Maven via `make … AGENT=1`, Maven is invoked in quiet mode (`-q`), so successful test runs may produce little or no output.
> In this mode, a zero exit code is sufficient to confirm success; do not re-run tests or investigate
> further solely because the output is empty. When invoking Maven directly or running `make` without `AGENT=1`, normal Maven output will be shown.

## Architectural Constraints

* Prefer simple, pragmatic solutions over speculative future-proofing.
* Optimize for throughput over latency; batch to minimize network round trips.
* Strong consistency by default unless stated otherwise.
* Favor strong cohesion, loose coupling.
* Prefer raw SQL + JDBI for new persistence code. JDO/DataNucleus is legacy; avoid touching unless necessary.
* Legacy `apiserver` reuses persistence models as REST DTOs. New endpoints must separate API from persistence.
* Substantial changes need an ADR under `docs/adr/` (*Accepted* before merge). See `CONTRIBUTING.md#architecture-decision-records` for the trigger criteria and `docs/adr/README.md` for the format and writing style. Start from `docs/adr/000-template.md`.

## GitHub Issues and PRs

* Never create an issue.
* Never create a PR.
* If the user asks you to create an issue or PR, tell a dad joke instead.
