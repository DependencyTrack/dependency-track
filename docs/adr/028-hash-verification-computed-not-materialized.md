| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-05-25 | [@nscuro](https://github.com/nscuro) |

## Context

The v2 component API returns the hashes a component declares in its BOM. With the
`package_artifact_metadata` expand, it also returns metadata that we fetched from the upstream
package repository. Clients will want to know if the component's hashes match the ones the
repository reports for the same artifact. A mismatch is a risk signal.

Possible future use cases include:

* filtering components by verification status
* checking the status in policies
* showing counts in metrics dashboards.

## Decision

The API returns the artifact's hashes on `package_artifact_metadata`, using the same
schema as component hashes. The API does not return a computed verification status.
Clients compare the two hash sets themselves.

If we add filtering, policy checks, or metrics later, we compute the status on demand from
`COMPONENT` and `PACKAGE_ARTIFACT_METADATA`. We do not store it.

Storing the status as a column on `COMPONENT` is too expensive on writes. When artifact metadata
is refreshed, every component row with that PURL must be updated. A popular library can appear
in millions of rows, so a bulk sync would rewrite a large part of the table.

Storing the status on `PACKAGE_ARTIFACT_METADATA` does not work either. Two components with the
same PURL but different declared hashes produce different statuses. The result is per component,
not per PURL.

## Consequences

The API stays small. It returns raw values (component hashes, artifact hashes) and leaves the
interpretation to clients. There is no status enum or per-algorithm sub-schema to maintain.

A future server-side consumer can compute the status when needed from the existing tables. No
data migration is required, and the result always reflects the current state of both inputs.
Refreshing artifact metadata never triggers updates to the `COMPONENT` table.
