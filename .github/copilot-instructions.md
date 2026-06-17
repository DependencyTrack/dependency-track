# Copilot Code Review Instructions

These instructions steer GitHub Copilot's automatic PR reviews. They complement `AGENTS.md` and `CONTRIBUTING.md`.

## Project context

Dependency-Track is an intelligent component analysis platform that allows organizations to identify and reduce risk in the software supply chain.
The repo is a multi-module Maven project. Relevant modules: `apiserver` (main application),
`api` (REST API v2, OpenAPI v3, spec-first), `alpine` (legacy framework being dissolved), `cache`, `common`, `dex` (durable execution),
`migration` (Flyway), `notification`, `plugin`, `proto`.

## Review priorities

Review in this order. Do not surface low-priority nits if higher-priority issues are present in the same change.

1. Security
2. Persistence and migration correctness
3. REST API conventions (v1 vs. v2)
4. Architectural change gate (ADR required?)
5. Code quality, performance, testing

---

## 1. Security (highest priority)

This is a security product. Be unapologetic about flagging insecure patterns.

- **SQL injection.** Flag any string concatenation or interpolation into SQL. Require JDBI bind parameters or `PreparedStatement` placeholders.
  - Bad: `handle.createQuery("SELECT * FROM project WHERE name = '" + name + "'")`
  - Good: `handle.createQuery("SELECT * FROM project WHERE name = :name").bind("name", name)`
- **Injection sinks.** Flag unvalidated user input flowing into: `Runtime.exec` / `ProcessBuilder`, file paths (`Paths.get`, `new File`), HTTP clients (SSRF), XML/JSON parsers without hardening (XXE, polymorphic deserialization), template engines, LDAP filters, regex compiled from user input.
- **AuthN/AuthZ.** Flag new REST endpoints that lack a permission check (`@PermissionRequired` or equivalent). Flag IDOR risk: lookups by UUID/ID that do not verify the caller has access to the target object.
- **Secrets and crypto.** Flag hardcoded credentials, API keys, or tokens. Flag MD5/SHA-1 used for security purposes, ECB mode, static IVs, hardcoded salts, `Random`/`ThreadLocalRandom` used to generate tokens or IDs (require `SecureRandom`).
- **Logging.** Flag log statements that include secrets, API keys, session tokens, raw request bodies, or PII. Flag `printStackTrace()` in production paths.
- **Dependencies.** Flag introduction of unmaintained or low-reputation libraries.

## 2. Persistence

- **New persistence code must use JDBI + raw SQL.** Flag new code in non-legacy paths that uses JDO (`PersistenceManager`, `@PersistenceCapable`, DataNucleus extensions). Existing JDO code in `apiserver` may be modified, but new entities and queries should be JDBI.
- **Schema changes need a Flyway migration.** If a PR adds/modifies a `@PersistenceCapable` field, JDBI mapping, or raw DDL without a corresponding migration under `migration/src/main/resources/org/dependencytrack/migration/`, flag it.
- **Strong consistency by default.** Flag transaction boundaries that look incorrect (long-running transactions, cross-service calls inside a transaction, missing rollback on error).
- **Throughput over latency.** Flag obvious N+1 patterns (loops issuing one query per element); suggest batching.

## 3. REST API conventions

- **New endpoints belong in API v2** (`api/src/main/openapi/`, spec-first). Flag PRs that add new JAX-RS resource classes or new endpoints under `apiserver/src/main/java/org/dependencytrack/resources/v1/` unless they extend existing v1 endpoints.
- **Separate API from persistence in v2.** Flag v2 DTOs that import or extend classes from `org.dependencytrack.model` or other JDO persistence packages. v2 must use dedicated request/response types.
- **v1 Swagger annotations.** When a v1 endpoint is touched, flag missing or stale `@Operation`, `@ApiResponse`, `@Parameter` annotations on the modified method.

## 4. Architectural change gate

Substantial changes require an Architecture Decision Record under `docs/adr/` (template at `docs/adr/000-template.md`). Flag PRs that introduce, remove, or significantly alter any of the following without a corresponding ADR file in the diff:

- A module, plugin extension point, or cross-module API.
- Database schema, persistence model, or data migration semantics (beyond routine column additions).
- A REST API contract change that is paradigm-shifting or breaking (new authN/authZ model, new API version, cross-cutting conventions). Routine new endpoints following existing conventions do *not* require an ADR.
- A runtime dependency, datastore, or external integration.
- Concurrency, consistency, or scalability characteristics of an existing subsystem.

When in doubt, ask the author whether an ADR was considered.

## 5. Code quality, performance, testing

- **No speculative future-proofing.** Flag added abstractions, interfaces, or config flags that have a single implementation/value and no near-term second use.
- **No new dependencies for trivial logic.** Flag added Maven dependencies whose functionality is available in the JDK or in libraries already on the classpath.
- **Comments.** Flag trivial comments that restate the code. Comments are only warranted for non-obvious *why*.
- **Error handling.** Flag broad `catch (Exception | Throwable)` that swallows or logs and continues. Flag empty catch blocks. Flag `catch` blocks that lose the original exception.
- **Concurrency.** Flag shared mutable state without synchronization.
- **Tests.** Flag new public methods, endpoints, or branches added without corresponding test coverage in the same PR. Prefer integration tests that exercise real persistence over heavy mocking when the area already has integration tests.

---

## What NOT to comment on

- Whitespace, indentation, or import ordering. These are enforced by `make lint-java`.
- Breaking changes in `proto/` or OpenAPI specs. CI lint (`make lint-proto`, `make lint-openapi`) catches these.
- PR title, description, or commit message wording.
- Style preferences that conflict with existing code in the same file. Consistency with surrounding code wins.
- Vague "consider improving readability" suggestions without a concrete alternative.
