# Project Structure

Dependency-Track is a multi-module Maven project.
The codebase started as a single Maven module and is being broken up into smaller modules over time.

> [!NOTE]
> Modularization is not only an architectural choice, it also drives the effectiveness of
> build parallelization and build caching.

## Top-level layout

Every top-level directory with a `pom.xml` is a Maven module.
Documentation, development tooling, and CI configuration live next to the modules at the repository root.

## Modules

### Core application

These modules carry product features.

* `api`: OpenAPI specification for REST API v2. Spec-first. New endpoints go here.
* `apiserver`: main application. Descended from the original single-module codebase.
   Hosts REST API v1 under `src/main/java/org/dependencytrack/resources/v1` and REST API v2
   implementations under `src/main/java/org/dependencytrack/resources/v2`.
* `notification`: notification API, publishers, and templating. Parts of the notification infrastructure still live
  under `apiserver/src/main/java/org/dependencytrack/notification` because they are coupled to internal models.
* `package-metadata`: resolves package metadata from package repositories.
* `vuln-analysis`: vulnerability analyzers (OSS Index, Snyk, Trivy, internal database).
* `vuln-data-source`: adapters for vulnerability feeds (NVD, GitHub, OSV).

### Shared building blocks

Small libraries reused across modules.

* `common`: focused shared libraries (e.g. `config`, `datasource`, `health`, `init`, `pagination`).
* `migration`: Flyway database migrations.
* `proto`: Protocol Buffer message definitions.

### Shared infrastructure

Cross-cutting services with a clear API and one or more providers behind it.

* `alpine`: forked framework that `apiserver` is built on. Being dissolved over time by moving code into other modules.
* `cache`: cache API and providers (e.g. `memory`, `database`).
* `dex`: durable execution engine.
* `file-storage`: file storage API and providers (e.g. `local`, `memory`, `s3`).
* `plugin`: plugin API and runtime used by other modules to load providers
  (e.g. notification publishers or vulnerability analyzers).
* `secret-management`: secret storage.

### Support libraries

Live under `support/`. Each one fills a small, well-scoped gap.

* `cyclonedx-proto`: CycloneDX Protocol Buffer definitions.
* `datanucleus-plugin`: custom DataNucleus ORM extensions.
* `flyway`: Support code for working with Flyway.
* `jdbi`: Support code for working with JDBI.
* `os-distro-metadata`: Linux distribution metadata.
* `smallrye-config-*`: SmallRye Config extensions.
* `swagger-model-converters`: Swagger and OpenAPI model converters.
* `v4-migrator`: tooling to migrate from Dependency-Track v4.

### Testing

* `coverage-report`: aggregator project for generating JaCoCo code coverage reports.
  Modules for which test coverage is to be captured are added as dependencies here.
* `e2e`: end-to-end tests.

## Top-level directories that are not modules

* `.github/`: GitHub workflows and issue templates.
* `.mvn/`: Maven configuration.
* `dev/`: local development tooling (Docker Compose stack, monitoring stack).
* `docs/`: contributor-facing documentation, including Architecture Decision Records under `docs/adr/`.
  User-facing documentation lives in a separate repository.

## Extending this document

* Keep one short paragraph per module.
* Place new modules into the group that best matches their role.
* Add a new group only if no existing one fits.
