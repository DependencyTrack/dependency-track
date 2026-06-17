| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-03-11 | [@nscuro](https://github.com/nscuro) |

## Context

To enable latest version checks, component age policies, and integrity verification,
we retrieve the corresponding metadata from upstream package repositories.

Currently, this data is persisted in the `REPOSITORY_META_COMPONENT` and `INTEGRITY_META_COMPONENT`
tables. Note that `INTEGRITY_META_COMPONENT` is a new construct introduced in v5,
while `REPOSITORY_META_COMPONENT` already existed in v4.

### `REPOSITORY_META_COMPONENT` schema

| Column          | Type        | Constraints |
|:----------------|:------------|:------------|
| ID              | BIGINT      | PK          |
| REPOSITORY_TYPE | TEXT        | NOT NULL    |
| NAMESPACE       | TEXT        |             |
| NAME            | TEXT        | NOT NULL    |
| LATEST_VERSION  | TEXT        |             |
| PUBLISHED       | TIMESTAMPTZ |             |
| LAST_CHECK      | TIMESTAMPTZ |             |

### `INTEGRITY_META_COMPONENT` schema

| Column         | Type        | Constraints      |
|:---------------|:------------|:-----------------|
| ID             | BIGINT      | PK               |
| PURL           | TEXT        | NOT NULL, UNIQUE |
| MD5            | TEXT        |                  |
| SHA1           | TEXT        |                  |
| SHA256         | TEXT        |                  |
| SHA512         | TEXT        |                  |
| PUBLISHED_AT   | TIMESTAMPTZ |                  |
| REPOSITORY_URL | TEXT        |                  |
| LAST_FETCH     | TIMESTAMPTZ |                  |
| STATUS         | TEXT        |                  |

### Issues and limitations

It is not possible to join the `COMPONENT` and `REPOSITORY_META_COMPONENT` tables:

* `COMPONENT` has `PURL` and `PURL_COORDINATES` (PURL without qualifiers and subpath) columns.
* `REPOSITORY_META_COMPONENT` has `REPOSITORY_TYPE`, `NAMESPACE` and `NAME` columns.
* `REPOSITORY_TYPE` is not necessarily the same as a PURL type.
* Namespace and name segments of full PURLs might be URL-encoded (e.g. `pkg:npm/%40foo/bar@1.0.0`).
* `NAMESPACE` and `NAME` columns of `REPOSITORY_META_COMPONENT` contain PURL namespace and name in URL-**decoded** form.

Thus:

* There is no single column we can join on.
* Constructing or deconstructing PURLs we can join on in the query is not reliable.

This causes a few bad limitations:

* When fetching data for the `/api/v1/finding/project/{uuid}` endpoint,
  we run into the N+1 problem because we can't join.
* It is impossible to delete `REPOSITORY_META_COMPONENT` records that refer to
  components that no longer exist in the portfolio. The table can thus only grow over time.

Finally, the wording of `REPOSITORY_META_COMPONENT` and `INTEGRITY_META_COMPONENT` is
confusing. Fundamentally what they describe is *package metadata* and *package artifact metadata*.

## Decision

Re-design the schema for this data to be more expressive, and easier to join.

`REPOSITORY_META_COMPONENT` becomes `PACKAGE_METADATA`. 
Its primary key is a PURL *without version, qualifiers, and subpath segments*,
e.g. `pkg:maven/com.acme/acme-lib`. It stores:

* The latest available version for the component.
* *Who* resolved this data (i.e., name of the resolver implementation).
* *When* it was resolved.
* *What source* it was resolved from (e.g. `maven-central`).

| Column         | Type        | Constraints |
|:---------------|:------------|:------------|
| PURL           | TEXT        | PK          |
| LATEST_VERSION | TEXT        |             |
| RESOLVED_BY    | TEXT        | NOT NULL    |
| RESOLVED_AT    | TIMESTAMPTZ | NOT NULL    |
| RESOLVED_FROM  | TEXT        |             |

Its purpose is to store information that applies to all versions of the package.
Note that `LATEST_VERSION` is now nullable. A `NULL` value here is used to signal
that resolution was attempted, but no data was found.

The `PUBLISHED` column from `REPOSITORY_META_COMPONENT` is effectively dropped.
Its presence was a design mistake, as it confused publish timestamps of the latest
version, with that of an actual artifact.

`INTEGRITY_META_COMPONENT` becomes `PACKAGE_ARTIFACT_METADATA`.
Its primary key is a full PURL, *including any qualifiers and subpaths*,
which enables it to be joined with `COMPONENT` records. It stores:

* Artifact hashes.
* The publish timestamp.
* *Who* resolved this data (i.e., name of the resolver implementation).
* *When* it was resolved.
* *What source* it was resolved from (e.g. `maven-central`).

| Column        | Type        | Constraints  |
|:--------------|:------------|:-------------|
| PURL          | TEXT        | PK           |
| PACKAGE_PURL  | TEXT        | FK, NOT NULL |
| HASH_MD5      | TEXT        |              |
| HASH_SHA1     | TEXT        |              |
| HASH_SHA256   | TEXT        |              |
| HASH_SHA512   | TEXT        |              |
| PUBLISHED_AT  | TIMESTAMPTZ |              |
| RESOLVED_BY   | TEXT        | NOT NULL     |
| RESOLVED_AT   | TIMESTAMPTZ | NOT NULL     |
| RESOLVED_FROM | TEXT        |              |

Its purpose is to store artifact-specific information. An important detail here is that
considering PURL qualifiers is *critical*. `pkg:maven/com.acme/acme-lib@1.2.3?type=jar`
and `pkg:maven/com.acme/acme-lib@1.2.3?type=pom` refer to different artifacts, despite
sharing the same coordinates. Their hashes and potentially even publish timestamps differ.

The `REPOSITORY_URL` column from `INTEGRITY_META_COMPONENT` is replaced with the combination
of `RESOLVED_BY` and `RESOLVED_FROM`. It's not always possible to link metadata to a single
URL, as sometimes multiple requests are required to assemble all necessary information.

The `PACKAGE_PURL` column has a foreign key constraint referencing the `PACKAGE_METADATA`
table. This enables clean joins from `COMPONENT` to `PACKAGE_METADATA`, for example:

```sql
SELECT "LATEST_VERSION"
  FROM "COMPONENT" AS c
 INNER JOIN "PACKAGE_ARTIFACT_METADATA" AS pam
    ON pam."PURL" = c."PURL"
 INNER JOIN "PACKAGE_METADATA" AS pm
    ON pm."PURL" = pam."PACKAGE_PURL"
 WHERE c."UUID" = '95d72ef7-a42f-4db6-9335-37aabe357315'
```

> [!NOTE]
> Package metadata resolution is fundamentally linked to PURL.
> No other identifier allows for accurate resolution and is thus not considered.
> Not all `COMPONENT` records have a PURL.

Every unique `COMPONENT.PURL` value should have a corresponding `PACKAGE_ARTIFACT_METADATA`
record with matching `PURL` column. When ingesting data from BOMs or REST API requests,
we already canonicalize PURLs, which means that qualifier ordering etc. is generally stable
and will not lead to duplicate `PACKAGE_ARTIFACT_METADATA` rows.

It also improves data consistency: Artifact metadata cannot exist without corresponding
package metadata, even if the latter is "unknown". However, it does force `PACKAGE_METADATA`
records to exist before `PACKAGE_ARTIFACT_METADATA` records can be created. Resolvers
are expected to always resolve both sets of information, and the logic that orchestrates
resolvers must ensure proper insertion order.

The names `PACKAGE_METADATA` and `PACKAGE_ARTIFACT_METADATA` better convey what the
data they're holding is about.

## Consequences

* The N+1 problem for endpoints like `/api/v1/finding/project/{uuid}` is eliminated.                                                                                                                      
  Package and artifact metadata can be fetched in a single query via joins.
* Orphaned metadata rows can be identified and cleaned up by left-joining
  against `COMPONENT`, preventing unbounded table growth.
* The FK from `PACKAGE_ARTIFACT_METADATA` to `PACKAGE_METADATA` enforces data consistency
  at the database level, but introduces a write-order dependency that all resolvers
  and their orchestration logic must respect.
* Existing data in `REPOSITORY_META_COMPONENT` and `INTEGRITY_META_COMPONENT`
  must be migrated. `REPOSITORY_META_COMPONENT` rows cannot be migrated losslessly
  because they lack a PURL — they will need to be re-resolved.