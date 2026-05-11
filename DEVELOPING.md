# Developing

> Please also read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

> [!IMPORTANT]
> Substantial changes must be accompanied by an [Architecture Decision Record](./docs/adr/).
> See the [criteria in `CONTRIBUTING.md`](./CONTRIBUTING.md#architecture-decision-records) before starting work.

## Prerequisites

* JDK 25+ ([Temurin](https://adoptium.net/temurin/releases) distribution recommended)
* Maven 3.9+
* Docker or Podman (required for [tests](#testing) and [dev mode](#dev-mode))
* A Java IDE (IntelliJ recommended)

> [!TIP]
> We recommend [sdkman](https://sdkman.io/) for managing JDK and Maven installations,
> and [mvnd](https://github.com/apache/maven-mvnd) for faster builds.
> The `Makefile` automatically uses `mvnd` when available, falling back to `mvn`.

> [!NOTE]
> This guide uses [`make`](https://www.gnu.org/software/make/) commands for brevity,
> and we recommend that you use `make` if you prefer CLI-centric workflows.
> If using `make` is not an option, you can inspect the full commands in [`Makefile`](Makefile)
> and use them for your own custom workflows.
> 
> For IDE-centric workflows, we provide equivalent IntelliJ [run configurations](.idea/runConfigurations).

## Core Technologies

| Technology                                                                                  | Purpose                   |
|:--------------------------------------------------------------------------------------------|:--------------------------|
| [Jakarta REST (JAX-RS)](https://projects.eclipse.org/projects/ee4j.rest)                    | REST API specification    |
| [Jersey](https://eclipse-ee4j.github.io/jersey/)                                            | JAX-RS implementation     |
| [OpenAPI](https://www.openapis.org/)                                                        | API specification         |
| [JDO](https://db.apache.org/jdo/)                                                           | Persistence specification |
| [DataNucleus](https://www.datanucleus.org/products/accessplatform/jdo/getting_started.html) | JDO implementation        |
| [JDBI](https://jdbi.org/)                                                                   | Database access           |
| [Flyway](https://www.red-gate.com/products/flyway/)                                         | Database migrations       |
| [MicroProfile Config](https://microprofile.io/specifications/microprofile-config/)          | Configuration             |
| [Jetty](https://www.eclipse.org/jetty/)                                                     | Servlet container         |
| [PostgreSQL](https://www.postgresql.org/)                                                   | Database                  |
| [Testcontainers](https://testcontainers.com/)                                               | Integration testing       |
| [Protocol Buffers](https://protobuf.dev/)                                                   | Serialization             |

## Architecture Constraints

The following constraints apply project-wide. They exist to keep the codebase coherent
as it evolves and to avoid steering changes in directions we are actively moving away from.
For substantial changes, see also the [Architecture Decision Record](./CONTRIBUTING.md#architecture-decision-records)
process in `CONTRIBUTING.md`.

### REST API v1 is in maintenance mode

New endpoints must be added to API v2, which lives in the [`api`](./api) module and follows
a spec-first OpenAPI workflow. API v1 (in [`apiserver/src/main/java/org/dependencytrack/resources/v1`](./apiserver/src/main/java/org/dependencytrack/resources/v1))
is code-first and uses Swagger annotations on JAX-RS resources. Touch v1 only when extending
or fixing existing endpoints.

API v1 also reuses persistence models as REST DTOs. Do not propagate that pattern into v2.
New endpoints must keep the API contract decoupled from the persistence layer.

### Persistence: prefer JDBI and raw SQL

JDO and DataNucleus are being phased out. New persistence code should use [JDBI](https://jdbi.org/)
with raw SQL. Avoid touching JDO entities unless the change genuinely requires it, and do not
build new features on top of the JDO layer.

### Throughput over latency

The system processes large volumes of components, vulnerabilities, and analyses. Optimize
for throughput. Batch work, minimize network round trips, and avoid per-record hot paths
that issue one query, request, or message at a time.

### Strong consistency by default

Default to strong consistency. Eventual consistency is acceptable only when the use case
explicitly demands it (typically for scale or availability reasons) and the trade-off is
documented.

### Simple and pragmatic over speculative future-proofing

Solve the problem in front of you. Avoid extra abstractions, configuration knobs, or
extension points introduced for hypothetical future needs. It is cheaper to add an
abstraction when a second concrete use case appears than to maintain one that has none.

### Strong cohesion, loose coupling

Modules should be small and focused, with narrow, intentional interfaces between them.
Reach across module boundaries through well-defined APIs rather than by importing
internals. The ongoing modularization effort moves the codebase in this direction.

## Building

Build the project:

```shell
make build
```

> [!TIP]
> (Re-) building the entire project via `make build` is cheap due to [build caching](#build-cache).
> You generally don't need to build modules selectively.

The resulting JAR is placed in `./apiserver/target` as `dependency-track-apiserver.jar`.
It ships with an embedded Jetty server, there's no need to deploy it in an application
server like Tomcat or WildFly.

Build a container image:

```shell
make build-image
```

This produces the image `ghcr.io/dependencytrack/apiserver:local`.

## Testing

Run all tests:

```shell
make test
```

Run a single test class:

```shell
make test-single MODULE=apiserver TEST=FooTest
```

Run multiple test classes:

```shell
make test-single MODULE=apiserver TEST="FooTest,BarTest"
```

Run a single test method:

```shell
make test-single MODULE=apiserver TEST="FooTest#testFoo"
```

Run e2e tests:

```shell
make test-e2e
```

## Dev Mode

Dev mode launches the API server with auto-provisioned containers for PostgreSQL
and the frontend. Containers are created on startup and disposed of on shutdown.

```shell
make apiserver-dev
```

The API server will be available at `http://localhost:8080`.
Frontend and PostgreSQL ports are logged during startup.

Dev mode specific configuration can be made in [`application-dev.properties`](apiserver/src/main/resources/application-dev.properties).

## DataNucleus Bytecode Enhancement

Classes annotated with `@PersistenceCapable` must be
[enhanced](https://www.datanucleus.org/products/accessplatform/jdo/enhancer.html)
post-compilation. Maven handles this automatically, but IDEs run their own builds
and may skip the enhancement step.

If you see `NucleusUserException: Found Meta-Data for class ... but this class is either not enhanced`
when running tests from your IDE, run:

```shell
make datanucleus-enhance
```

Then re-run the test. Ensure your IDE is not cleaning the `target` directory before execution.

## Database Migrations

Schema changes are managed with [Flyway](https://www.red-gate.com/products/flyway/).
The API server owns the schema and applies pending migrations at startup.

Migrations live in [`migration/src/main/resources/org/dependencytrack/migration`](migration/src/main/resources/org/dependencytrack/migration)
and follow Flyway's naming convention:

* `V<timestamp>__<description>.sql` for versioned migrations, applied once in timestamp order.
  `<timestamp>` is `YYYYMMDDHHMM` (UTC).
* `R__<name>.sql` for repeatable migrations (stored procedures, functions, views).
  Reapplied automatically when their content changes.

### Adding a Migration

Scaffold a new versioned migration:

```shell
make new-migration NAME="add foo column to bar"
```

This creates an empty `V<timestamp>__add_foo_column_to_bar.sql` file. Add your DDL/DML to it.

For repeatable migrations, edit the relevant `R__*.sql` file directly, no new file needed.

> [!IMPORTANT]
> Do not modify versioned migrations already merged to `main`.
> Flyway rejects checksum mismatches on existing deployments.
> Add a new migration instead.

## Build Cache

We use Maven [build caching](https://maven.apache.org/extensions/maven-build-cache-extension/) to speed
up builds. If you encounter stale or unexplainable build issues, try clearing the cache and see if it
resolves your issues:

```shell
make clean-build-cache
```
