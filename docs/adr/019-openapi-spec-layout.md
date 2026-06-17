| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-04-27 | [@nscuro](https://github.com/nscuro) |

## Context

The OpenAPI v2 spec was authored as a split tree under `api/src/main/openapi/`:
a root `openapi.yaml` referencing path files under `paths/` and component
schemas, parameters, and responses under `components/`. The layout grew
ad-hoc and showed three problems that were going to compound as more resources
were added.

First, schema grouping was inconsistent. The first three resources to be added
after the initial set (`extensions`, `secrets`, `vuln-policies`) created
subdirectories under `components/schemas/`, while the older resources
(`components`, `projects`, `task-queues`, `workflow-runs`) sat at the root.
With ~50 schemas already, "which schemas belong to projects" required `grep`.

Second, path filenames encoded URL paths with two competing separator
conventions (`__name__` vs `_uuid_`) and produced names like
`extension-points__name__extensions__name__config-schema.yaml`. The encoding
was brittle and the result hostile to read.

Third, paths and the schemas they used were not co-located. Adding an endpoint
touched files across two trees with no physical link between them, and a new
contributor had to guess the mapping.

A resource-grouped layout, modeled on
[digitalocean/openapi](https://github.com/digitalocean/openapi), was considered
and adopted. DigitalOcean publishes one of the larger spec-first OpenAPI
specifications in the open and structures everything around the resource
(tag) it belongs to.

A more granular variant was prototyped and rejected. It would have used one
file per HTTP operation, with the root spec stitching method-level `$ref`s
under each path key. The OpenAPI 3.0 specification only allows `$ref` at the
PathItem level, not under individual operations. `openapi-generator` enforces
this and silently drops the operations when validation is bypassed. Supporting
per-operation files would have required a `redocly bundle` step in the build,
which adds a Node toolchain dependency for marginal organisational benefit.

## Decision

Adopt a resource-grouped layout. Each tag in `openapi.yaml` corresponds to a
directory under `resources/`. That directory holds every path file for the
resource and a `schemas/` subdirectory for the schemas it owns. Cross-resource
components live under `shared/{parameters,responses,schemas}/`.

Each path file holds all HTTP methods for one URL. The root spec binds each
URL to its path file with a single `$ref`. Path filenames are descriptive of
the path's purpose (`secret.yaml`, `vuln-policy-bundle-sync.yaml`), kebab-case
throughout. Path-level keys (`parameters`, `summary`, `description`, `servers`)
are forbidden, since the single-`$ref` stitching cannot express them. Every
operation duplicates its own path parameters, as it already did.

Schema basenames are globally unique across `**/schemas/**`. `openapi-generator`
derives the generated Java class name from the filename stem, so duplicates
would silently drop one class. The resource prefix is part of the filename
when needed for disambiguation (`list-vuln-policy-bundles-response-item.yaml`).
Uniqueness is enforced by a small shell check wired into `make lint-openapi`.

Spectral gains one new rule: every operation must declare exactly one tag,
drawn from the canonical list in `openapi.yaml` (built-in
`operation-tag-defined` raised to error, plus a cardinality check).

## Consequences

Adding a new resource is a directory creation. Adding an endpoint is one path
file plus its schemas in the resource's own `schemas/` directory plus one
binding in `openapi.yaml`. The mapping between paths and schemas is now a
structural property of the tree rather than a convention enforced through
review.

The published bundled spec (`openapi-v2.yaml` consumed by the docs site) is
byte-identical before and after the restructure, so no client-visible behaviour
changes. The generated Java model and API class set is unchanged.

Schema basename uniqueness is a global property that shows up first as a
build-time class-name collision, which is hard to debug after the fact. The
shell-based uniqueness check fails fast on `make lint-openapi`.
