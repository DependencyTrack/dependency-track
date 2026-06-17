| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2025-06-11 | [@nscuro](https://github.com/nscuro) |

## Context

Version 1 of the REST API suffers from various inconsistencies and ambiguities.

A few examples of related issues:

* <https://github.com/DependencyTrack/dependency-track/issues/4804>
* <https://github.com/DependencyTrack/dependency-track/issues/4867>
* <https://github.com/DependencyTrack/dependency-track/issues/4899>
* <https://github.com/DependencyTrack/dependency-track/issues/4914>
* <https://github.com/DependencyTrack/dependency-track/issues/4926>
* <https://github.com/DependencyTrack/dependency-track/issues/4929>
* <https://github.com/DependencyTrack/dependency-track/issues/4938>
* <https://github.com/DependencyTrack/dependency-track/issues/4940>
* <https://github.com/DependencyTrack/dependency-track/issues/4977>

The primary causes of this are:

* The [OpenAPI] spec is generated from code and annotations, which is inaccurate at times.
* There is no automated enforcement of conventions to ensure consistency regarding path naming,
casing, parameter names and more.
* Because the spec is generated at runtime, maintainers and contributors won't see it during development
or during PR reviews. It is invisible when it arguably matters most, i.e., when the API changes.
* Persistence model classes are used for API requests and responses. This provides wrong impressions
as to what data is required in requests, and what data is returned in responses.

## Decision

### Going Spec-First

Instead of generating an [OpenAPI] specification from code and annotations, generate code from an [OpenAPI] spec.

This will ensure that:

* The spec becomes the source of truth for the API contract.
* Contributors get a complete picture of the API surface more easily.
* Incorrect or partial implementations are caught early (would cause build failures).
* It becomes impossible to abuse persistence models for REST API interactions.
* Consistency can be enforced in CI using linting tools.
* Users have higher confidence in the correctness of the spec when generating client code from it.

For the API server, code generation **must** involve:

* Interfaces for REST endpoints, which the API server then implements.
* Models for request and response objects.

### Introduction

Implementing the proposed changes retroactively for API v1 is likely to cause breaking changes,
or be a massive undertaking.

Instead, the proposed procedure is to only implement them for v2. Going forward, this means:

* New endpoints **must** be added to v2.
* Existing v1 endpoints are **not** ported to v2.
* Existing v1 endpoints are deprecated and slowly phased out as v2 replacements become available.

### Implementation

Leverage the [openapi-generator] project and its [jaxrs-spec generator].
A [Maven plugin](https://openapi-generator.tech/docs/plugins#maven) is available.

Isolate the spec and associated code generation in its own Maven module.

To ensure API consistency, use an OpenAPI linter. The tool of choice is [Spectral], 
which enjoys [broad industry adoption](https://github.com/stoplightio/spectral#-real-world-rulesets).
Alternative Spectral-compatible tooling is available as well, an example being [vacuum].

Linting **must** be part of the CI pipeline, and *should* be part of local Maven builds.
For the latter, it **must** be possible to skip linting when the `quick` profile is used.

An initial implementation of this can be found here: <https://github.com/DependencyTrack/hyades-apiserver/pull/1245>

## Consequences

* Due to their separation, API v1 and v2 will also produce separate OpenAPI specs.
* Contributors will need to make themselves familiar with [OpenAPI].
* Conventions etc. need to be defined and, preferably, encoded in [Spectral] rulesets so they can be enforced.

[OpenAPI]: https://swagger.io/docs/specification/v3_0/about/
[Spectral]: https://github.com/stoplightio/spectral
[jaxrs-spec generator]: https://openapi-generator.tech/docs/generators/jaxrs-spec
[openapi-generator]: https://openapi-generator.tech/
[vacuum]: https://github.com/daveshanley/vacuum