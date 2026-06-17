# api

Source-of-truth for Dependency-Track's REST API v2, in [OpenAPI v3.0] format.
The spec is split across many small files and assembled at build time by
[`openapi-generator`][openapi-generator], which produces JAX-RS interfaces and
Java DTOs.

The API draws inspiration from [Zalando's RESTful API Guidelines][zalando].
Conformance to those guidelines and to project conventions is enforced with
[spectral] in CI:

```shell
make lint-openapi
```

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

Resource directories map 1:1 to tags declared in `openapi.yaml`. A path file
under `resources/<r>/` is referenced from `openapi.yaml` via a single `$ref`.

## Conventions

- **One file per URL.** A path file holds *all* HTTP methods for one URL.
  OpenAPI 3.0 only allows `$ref` at the PathItem level, not under individual
  methods.
- **Filenames are kebab-case.**
- **Schema basenames are globally unique** across `**/schemas/**`. The generated
  Java class name is derived from the filename stem, so collisions would silently
  drop a class. Enforced by `make lint-openapi`.
- **Cross-resource `$ref`s only into `shared/`.** A path or schema under
  `resources/<a>/` may not reference files under `resources/<b>/`. Promote to
  `shared/` when reuse arises.
- **Tags.** Every operation must declare exactly one tag, drawn from the
  canonical list in `openapi.yaml`. Enforced by spectral.

## Adding an endpoint

1. Decide which resource (tag) owns it. If new, add a tag entry to
   `openapi.yaml` and create `resources/<resource>/`.
2. Create the path file at `resources/<resource>/<noun>.yaml` with all of its
   HTTP methods.
3. Place new request/response schemas under `resources/<resource>/schemas/`.
   Promote shared shapes to `shared/schemas/`.
4. Add the URL ↔ file mapping to `openapi.yaml`'s `paths:` section.
5. Run `make lint-openapi` and `make build` to verify.

[OpenAPI v3.0]: https://spec.openapis.org/oas/v3.0.3.html
[zalando]: https://opensource.zalando.com/restful-api-guidelines/
[openapi-generator]: https://github.com/OpenAPITools/openapi-generator
[spectral]: https://github.com/stoplightio/spectral
