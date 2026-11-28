# api

This module holds the source of truth for Dependency-Track's REST API v2, in [OpenAPI v3.0] format.
The spec spans many small files.
At build time, [`openapi-generator`][openapi-generator] assembles them and generates JAX-RS interfaces and Java DTOs.

The API draws inspiration from [Zalando's RESTful API Guidelines][zalando].
[Spectral][spectral] checks the spec against those guidelines and the project's own rules, locally and in CI:

```shell
make lint-openapi
```

Rules marked *Linted.* fail `make lint-openapi`.
Review catches the rest.

## Layout

```
src/main/openapi/
  openapi.yaml                      # info, tags, security, top-level path bindings
  shared/                           # cross-resource components
    parameters/
    responses/
    schemas/
  resources/<resource>/             # one directory per API tag
    <noun>[-<qualifier>].yaml       # one file per URL (all methods for that path)
    schemas/                        # schemas owned by this resource
```

## Conventions

- **One file per URL.** A path file holds *all* HTTP methods for one URL.
  OpenAPI 3.0 allows `$ref` only on a whole path item, not on single methods.
  The file's top level is the methods map itself, with no enclosing `"/path":` key.
- **Filenames are kebab-case.** Path files take their name from the URL:
  `secrets.yaml` for `/secrets`, `secret.yaml` for `/secrets/{name}`,
  and `project-clone.yaml` for an action or nested path.
- **Request and response schema files follow `<verb>-<resource>-<request|response>[-item].yaml`.**
  Examples are `create-secret-request.yaml` and `list-vuln-policies-response-item.yaml`.
- **Schema basenames are unique across all `schemas/` directories.**
  openapi-generator derives the Java class name from the filename stem, so a duplicate would silently drop a class.
  *Linted.*
- **Cross-resource `$ref`s go only into `shared/`.**
  A path or schema under `resources/<a>/` must not reference files under `resources/<b>/`.
  Move a file to `shared/` once a second resource needs it.
- **Enums get their own schema file when more than one schema uses them.** One-off enums can stay inline.
- **Every operation has exactly one tag.**
  It must come from the canonical list in [`openapi.yaml`](src/main/openapi/openapi.yaml). *Linted.*
- **`openapi.yaml` declares security for all operations.** Declare it on an operation only to override it.

## Adding an endpoint

1. Decide which resource tag owns the endpoint.
   For a new tag, add an entry to the `tags:` list in [`openapi.yaml`](src/main/openapi/openapi.yaml)
   and create `resources/<resource>/`.
2. Create the path file at `resources/<resource>/<noun>.yaml` with all of its HTTP methods.
   Follow the [design rules](#design-rules).
3. Put new request and response schemas under `resources/<resource>/schemas/`.
   Move shapes that several resources use to `shared/schemas/`.
4. Map the URL to the file in the `paths:` section of `openapi.yaml`.
5. Run `make lint-openapi`, `make lint-openapi-breaking`, and `make build`.

## Design rules

The `info.description` in [`openapi.yaml`](src/main/openapi/openapi.yaml) documents the conventions API clients see.
It covers pagination, filtering, sorting, field expansion, errors, authentication, deprecation, and internal operations.
New endpoints must follow it.
This section covers how to express those conventions in the spec.

### Naming

| Element          | Convention         | Example                    |
|:-----------------|:-------------------|:---------------------------|
| Property names   | `snake_case`       | `affected_component_count` |
| Path segments    | kebab-case         | `/vuln-policies`           |
| Path parameters  | `snake_case`       | `parent_uuid`              |
| Query parameters | `snake_case`       | `sort_by`                  |
| Enum values      | `UPPER_SNAKE_CASE` | `AT_LEAST`                 |

`make lint-openapi` fails on every row except enum values, which only get a warning.

### Identifiers and timestamps

- **Fields named `uuid` or `*_uuid` use `format: uuid`.** *Linted.*
  Never expose internal numeric database IDs.
- **Timestamps are epoch milliseconds, not ISO 8601 as Zalando recommends.**
  Reference [`shared/schemas/timestamp.yaml`](src/main/openapi/shared/schemas/timestamp.yaml)
  instead of a `date` or `date-time` format. *Linted.*

### Requests and responses

| Method   | `operationId` prefix                      | Success response               |
|:---------|:------------------------------------------|:-------------------------------|
| `GET`    | `get` or `list`                           | `200` with the resource        |
| `POST`   | none of `get`, `list`, `update`, `delete` | `201` with a `Location` header |
| `PUT`    | `update`                                  | `204`, no body                 |
| `PATCH`  | `update`                                  | `204`, no body                 |
| `DELETE` | `delete`                                  | `204`, no body                 |

`make lint-openapi` checks the prefixes, the `Location` headers, and the status codes of every method except `GET`.
The ruleset exempts `POST` on `/oauth/token` and on paths ending in `/test`.

- **Create and update responses carry no resource body.** A `201` may carry server-generated identifiers.
  Add them when the identifier is hard to extract from the `Location` URL.
  Asynchronous or fire-and-forget creates may return `202` with a `Location` header, or `204`.
- **`PATCH` returns `204`,** even though the linter also permits `200` with a body.
- **Requests and responses use separate schemas, even when they look alike.** A resource typically has these:
  `create-<r>-request`, `update-<r>-request`, `list-<r>s-response`, `list-<r>s-response-item`,
  and an optional `get-<r>-response` that extends the list item via `allOf`.
  When the list item and the single-resource response have the same shape, reference one schema from both.
  Requests and responses can share field-level schemas, including objects and enums.
- **`PATCH` request bodies make every property optional.**

### Pagination, sorting, and filtering

- **List responses extend [`shared/schemas/paginated-response.yaml`](src/main/openapi/shared/schemas/paginated-response.yaml) via `allOf`.**
  Schemas that extend it declare a required `items` array and no other array properties. *Linted.*
  List operations take the `page-token` and `pagination-limit` parameters
  from [`shared/parameters/`](src/main/openapi/shared/parameters).
  If a list can only report a lower bound for `total`, say so in the operation description.
- **`paginated-response.yaml` sets `x-parent: true`.**
  That makes openapi-generator emit Java inheritance for schemas that extend it.
  Set it on any other base schema used the same way.
- **Sorting uses the shared `sort-by` and `sort-direction` parameters.**
  List the supported `sort_by` values in the operation description.
  Endpoints without sorting take neither parameter.
- **Filter names use the suffixes `openapi.yaml` defines.**
  Examples are `created_since`, `created_before`, `name_contains`, `purl_prefix`, and `tags_all`.
- **List the valid `expand` values in the operation description.**

### Errors

- **Error responses use `application/problem+json`, not `application/json`.**
  Reusable responses live in `shared/responses/`.
- **Every operation declares a `default` response.**
  It references [`shared/responses/generic-error.yaml`](src/main/openapi/shared/responses/generic-error.yaml).
- **A `400` response takes one of two forms.**
  - [`shared/responses/invalid-request-error.yaml`](src/main/openapi/shared/responses/invalid-request-error.yaml),
    when generic request validation is the only possible `400`.
    An example is a `GET` that only validates query parameters.
  - An inline `anyOf`, when the endpoint can also reject with an endpoint-specific problem,
    or with a generic `problem-details.yaml` for other rejects.
    Most write endpoints need this form:

    ```yaml
    "400":
      description: Bad Request
      content:
        application/problem+json:
          schema:
            anyOf:
              - $ref: "../../shared/schemas/invalid-cel-expression-problem-details.yaml"
              - $ref: "../../shared/schemas/invalid-request-problem-details.yaml"
              - $ref: "../../shared/schemas/problem-details.yaml"
    ```

    Endpoint-specific problem schemas go in the resource's own `schemas/` directory,
    unless several resources share them.

### Validation constraints

- Every string property in a request body or parameter has a `maxLength`.
- Array properties have a `maxItems` where a reasonable upper bound exists.
- Integer and number properties declare a `format`, e.g. `int32`, `int64`, or `double`. *Linted.*

### Internal operations

Paths under `/internal/**` follow the same layout and rules, but sit outside the stable contract.
Breaking changes there are acceptable when `make lint-openapi-breaking` flags them.

[OpenAPI v3.0]: https://spec.openapis.org/oas/v3.0.3.html
[zalando]: https://opensource.zalando.com/restful-api-guidelines/
[openapi-generator]: https://github.com/OpenAPITools/openapi-generator
[spectral]: https://github.com/stoplightio/spectral
