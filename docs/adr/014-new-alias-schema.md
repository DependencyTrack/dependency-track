| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-02-23 | [@nscuro](https://github.com/nscuro) |

## Context

Vulnerability aliases are stored in the denormalized `VULNERABILITYALIAS` table:

| Column      | Type   | Constraints      |
|:------------|:-------|:-----------------|
| ID          | BIGINT | PK               |
| CVE_ID      | TEXT   |                  |
| GHSA_ID     | TEXT   |                  |
| GSD_ID      | TEXT   |                  |
| INTERNAL_ID | TEXT   |                  |
| OSV_ID      | TEXT   |                  |
| SNYK_ID     | TEXT   |                  |
| SONATYPE_ID | TEXT   |                  |
| VULNDB_ID   | TEXT   |                  |
| UUID        | UUID   | NOT NULL, UNIQUE |

This design poses a few challenges:

* Rows lack a natural key, making it impossible to detect and prevent duplicates.
* Modifying rows (i.e. adding a new ID to an existing alias group) is prone to race conditions.
* Due to the combination of the points above, batching operations on this table is not possible.
* Vulnerability sources are hardcoded as columns, making it unnecessarily challenging to add new sources.
* Querying the table is unnecessarily hard, as it requires the caller to know what column to query on.
* The lack of provenance for alias relationships prevents safe removal of relationships,
  e.g. when upstream sources correct their data.

The [logic to create or modify alias records](https://github.com/DependencyTrack/hyades-apiserver/blob/f969a32387c03b45eff186e2fcc4ba900a7059f9/apiserver/src/main/java/org/dependencytrack/persistence/VulnerabilityQueryManager.java#L474-L591)
is brittle and non-deterministic. Making it concurrency-safe would require acquisition of coarse advisory locks.

Alias synchronization unfortunately is in the hot path for vulnerability analysis result reconciliation,
and is performed concurrently with potentially overlapping data. To ensure that synchronization is both
performant and correct, we need a solution that allows us to batch database operations,
while effectively shielding us against data races.

## Decision

### Schema

Normalize the data into a new `VULNERABILITY_ALIAS` table with the following schema:

| Column   | Type | Constraints |
|:---------|:-----|:------------|
| GROUP_ID | UUID | NOT NULL    |
| SOURCE   | TEXT | PK          |
| VULN_ID  | TEXT | PK          |

* The separate ID columns are collapsed into `SOURCE` and `VULN_ID`.
* `SOURCE` and `VULN_ID` form the natural (primary) key, effectively preventing duplicates.
* Alias relationships are identified via matching `GROUP_ID`.

### Querying

To query all aliases of a vulnerability identified by `source` and `vulnId`, *excluding the input pair itself*:

```sql linenums="1"
SELECT va.*
  FROM "VULNERABILITY_ALIAS" AS va
 WHERE va."GROUP_ID" IN (
   SELECT va2."GROUP_ID"
     FROM "VULNERABILITY_ALIAS" AS va2
    WHERE va2."SOURCE" = :source
      AND va2."VULN_ID" = :vulnId
 )
   AND (va."SOURCE", va."VULN_ID") != (:source, :vulnId)
```

### Alias Assertions

To track provenance of alias relationships, a separate `VULNERABILITY_ALIAS_ASSERTION` table records
which entity asserted that two vulnerabilities are aliases:

| Column       | Type           | Constraints             |
|:-------------|:---------------|:------------------------|
| ASSERTER     | TEXT           | PK                      |
| VULN_SOURCE  | TEXT           | PK                      |
| VULN_ID      | TEXT           | PK                      |
| ALIAS_SOURCE | TEXT           | PK                      |
| ALIAS_ID     | TEXT           | PK                      |
| CREATED_AT   | TIMESTAMPTZ(3) | NOT NULL, DEFAULT NOW() |

Each row records that `ASSERTER` claimed (`VULN_SOURCE`, `VULN_ID`) and (`ALIAS_SOURCE`, `ALIAS_ID`)
are aliases. Assertions are directional: (`VULN_SOURCE`, `VULN_ID`) is the declaring vulnerability,
(`ALIAS_SOURCE`, `ALIAS_ID`) is the alias attributed to it. This enables efficient reconciliation
by querying existing assertions for a given vulnerability.

Alias groups in the `VULNERABILITY_ALIAS` table are derived from assertions and serve as a
materialized view for efficient read queries. They are recomputed whenever assertions change.
Assertions provide an audit trail and enable workflows such as revoking assertions from
a specific source, without affecting others.

### Synchronization Algorithm

Given an asserter (e.g. `NVD`) and a map of declaring vulnerabilities to their asserted aliases:

```js linenums="1"
{
  {source: 'NVD', vulnId: 'CVE-1'}: [
    {source: 'GITHUB', vulnId: 'GHSA-1'},
    {source: 'SNYK', vulnId: 'SNYK-1'}
  ]
}
```

1. Begin transaction.
2. Acquire PostgreSQL advisory locks for all declaring vulnerabilities,
   ordered by key to prevent deadlocks between concurrent transactions:
   ```sql linenums="1"
   SELECT PG_ADVISORY_XACT_LOCK(HASHTEXT(key))
     FROM (
       SELECT DISTINCT UNNEST(ARRAY['vuln-alias-sync|NVD|CVE-1']) AS key
        ORDER BY 1
     ) AS t
   ```
3. Fetch existing assertions for the declaring vulnerabilities:
   ```sql linenums="1"
   SELECT "ASSERTER"
        , "VULN_SOURCE"
        , "VULN_ID"
        , "ALIAS_SOURCE"
        , "ALIAS_ID"
     FROM "VULNERABILITY_ALIAS_ASSERTION"
    WHERE ("VULN_SOURCE", "VULN_ID") IN (SELECT * FROM UNNEST(:sources, :vulnIds))
   ```
4. Reconcile incoming aliases against existing assertions, scoped to the current asserter:
    * Assertions to create: incoming alias keys minus existing alias keys for this asserter.
    * Assertions to delete: existing alias keys for this asserter minus incoming alias keys.
    * `UNKNOWN` cleanup: if the asserter is not `UNKNOWN` and `UNKNOWN` assertions
      exist for the same declaring vulnerability, mark it for removal.
5. Delete stale assertions:
   ```sql linenums="1"
   DELETE
     FROM "VULNERABILITY_ALIAS_ASSERTION"
    WHERE ("ASSERTER", "VULN_SOURCE", "VULN_ID", "ALIAS_SOURCE", "ALIAS_ID")
       IN (SELECT * FROM UNNEST(:asserters, :vulnSources, :vulnIds, :aliasSources, :aliasIds))
   ```
6. Create new assertions:
   ```sql linenums="1"
   INSERT INTO "VULNERABILITY_ALIAS_ASSERTION" (
     "ASSERTER"
   , "VULN_SOURCE"
   , "VULN_ID"
   , "ALIAS_SOURCE"
   , "ALIAS_ID"
   )
   SELECT *
     FROM UNNEST(:asserters, :vulnSources, :vulnIds, :aliasSources, :aliasIds)
   ```
7. Delete `UNKNOWN` assertions for declaring vulnerabilities where a real asserter now provides claims:
   ```sql linenums="1"
   DELETE
     FROM "VULNERABILITY_ALIAS_ASSERTION"
    WHERE "ASSERTER" = 'UNKNOWN'
      AND ("VULN_SOURCE", "VULN_ID") IN (SELECT * FROM UNNEST(:sources, :vulnIds))
   ```
8. Recompute alias groups for all modified vulnerabilities:
    1. Expand transitively: iteratively query both `VULNERABILITY_ALIAS` and
       `VULNERABILITY_ALIAS_ASSERTION` to discover all transitively related keys.
       For example, if `CVE-1` is being linked to `GHSA-1`, but `GHSA-1` already
       has an assertion linking it to `GHSA-2`, expansion ensures `GHSA-2` is included.
    2. Build a [union-find] from the expanded assertions to compute [connected components].
    3. For each component, pick the lowest existing group UUID (deterministic via sorted set),
       or generate a new one if the component has no prior group.
    4. Upsert alias records, only writing when the group ID actually changed:
       ```sql linenums="1"
       INSERT INTO "VULNERABILITY_ALIAS" AS va ("GROUP_ID", "SOURCE", "VULN_ID")
       SELECT * FROM UNNEST(:groupIds, :sources, :vulnIds)
       ON CONFLICT ("SOURCE", "VULN_ID") DO UPDATE
       SET "GROUP_ID" = EXCLUDED."GROUP_ID"
       WHERE va."GROUP_ID" IS DISTINCT FROM EXCLUDED."GROUP_ID"
       ```
    5. Delete orphaned aliases no longer backed by any assertion.
9. Commit transaction and release locks (implicit).

> [!NOTE]
> Advisory locks are scoped to *declaring* vulnerability only. This is sufficient because
> assertions are directional: a given asserter always writes assertions under the declaring
> vulnerability it owns (e.g. NVD writes assertions under `NVD|CVE-*`).

All `SELECT`, `DELETE`, and `INSERT` operations are batched via `UNNEST`, allowing multiple
vulnerabilities to be processed in a single transaction with minimal round trips.
The upsert's `WHERE ... IS DISTINCT FROM` clause avoids unnecessary writes.

### Data Migration

Existing data is migrated from `VULNERABILITYALIAS` to `VULNERABILITY_ALIAS` via Liquibase.
The migration replicates the [synchronization algorithm](#synchronization-algorithm) in SQL.

The old `VULNERABILITYALIAS` table is dropped afterwards.

Assertions are seeded from the migrated alias groups. For each group, one assertion per unordered
pair of members is inserted with `ASSERTER = 'UNKNOWN'`, since the original data does not carry
provenance information.

An integration test verifies that the migration works as expected,
including the handling of potential duplicates in the existing data set,
and the correctness of seeded assertions.

## Consequences

* Adding new vulnerability sources requires no schema changes.
* Alias synchronization can be fully batched, reducing round trips in the hot path.
* The natural primary key prevents duplicate alias entries by construction.
* Querying aliases is uniform, and callers no longer need source-specific column knowledge.
* The old `UUID` column is dropped. Any external references to alias records by UUID will break.
  No known external consumers depend on this identifier.
* Advisory locks add contention under concurrent writes to overlapping alias sets.
  This is bounded by the lock granularity (per declaring vulnerability key), and acceptable
  given the correctness guarantees it provides.
* Alias group recomputation requires transitive expansion, which issues additional queries.
  In practice, alias groups are small (< 5 members), so this is negligible.
* Alias assertions provide provenance but grow linearly with the number of aliases per
  declaring vulnerability. Given the small expected group sizes, this is acceptable.
* `UNKNOWN` assertions seeded during migration are automatically superseded when a real
  asserter (e.g. NVD, GitHub) provides claims for the same declaring vulnerability.

[connected components]: https://en.wikipedia.org/wiki/Component_(graph_theory)
[union-find]: https://en.wikipedia.org/wiki/Disjoint-set_data_structure