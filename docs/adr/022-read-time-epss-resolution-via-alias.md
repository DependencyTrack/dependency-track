| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-05-11 | [@nscuro](https://github.com/nscuro) |

## Context

[EPSS][epss] is a CVE-level signal published daily by [FIRST][first-org].
It is stored in a dedicated `EPSS` table keyed by CVE ID. 
The FIRST mirror is the sole writer. The table has no provenance column.

Some vulnerability data sources publish EPSS values of their own, scoped to the
identifiers they own. Accepting those values would mean a second writer competes for
the same CVE-keyed rows. Without provenance there is no way to attribute or prioritise
either value, so the last writer wins per source and per cycle. Coverage is also
asymmetric: any non-authoritative source covers only the subset of CVEs it tracks.

The alias schema (see [ADR-014][adr-014]) already groups equivalent vulnerability identifiers
across sources by shared group identifier, so a non-CVE vulnerability can be linked to its
CVE sibling at query time. Sorting and filtering by EPSS happens in SQL today and must keep working.

## Decision

EPSS is owned by one authoritative source. We will keep the FIRST mirror as the
sole writer and not accept EPSS values from any vulnerability data source.

We will resolve EPSS at read time by joining through the alias group. A CVE-sourced
vulnerability resolves directly. A non-CVE vulnerability inherits the EPSS of its CVE
sibling. When the alias group contains multiple CVEs, the most impactful record is
returned, ordered by score, then by percentile, then by CVE identifier.

The resolution is expressed inline at each read site as a correlated `LEFT JOIN LATERAL`,
parameterized by the caller's source and vulnerability identifier. The branch that does
not match the caller's source still executes, but its predicate is unsatisfiable so it
reduces to an empty index probe rather than a row-producing scan. Each call therefore
performs effectively one index seek path. Sort and filter on score and percentile
remain pure SQL.

### Rejected alternatives

#### SQL view

A view that callers join by name is the intuitive design, but neither form we tried
performs acceptably at realistic data volumes.

A view that picks the per-group best record via a window function acts as a planner
optimisation fence: PostgreSQL cannot fold it into the surrounding query, so every
join materialises the full candidate set before the outer filter applies. This is the
same mechanism that prevents predicate pushdown into `WITH ... AS MATERIALIZED`
queries.[^pg-with]

A reformulation without a window function is foldable into the parent query, but the
planner still does not push the caller's `(source, vuln_id)` predicates into the
relevant part of the resolution. The candidate set is materialised regardless.
Disabling hash and merge joins to force per-row evaluation produces a worse plan,
because the predicates surface as residual filters above the materialised set.

The lateral form sidesteps the planner by writing the parameterisation explicitly into
the query. Its cost scales with caller size, whereas the view's cost scales with size
of the `EPSS` table.

#### Provenance column on `EPSS` table

Adding a `SOURCE` column to `EPSS` and changing the primary key to `(SOURCE, CVE)`
would let multiple mirrors write without overwriting each other. Reads would pick a
value via a fixed source priority (e.g. FIRST wins, others as fallback) or aggregate
across sources.

EPSS has a single methodology, owned by FIRST. Other sources that surface EPSS values
republish FIRST's data. Storing both yields two copies of the same number with no
independent signal, plus a priority policy that has to deal will mirror-lag
discrepancies forever.

Provenance also does not remove the alias join. A non-CVE vulnerability with no EPSS
row of its own still needs to resolve through its CVE sibling, so the lateral
resolution stays. Provenance would add a second mechanism on top of it rather than
replace it.

## Consequences

Any vulnerability with a CVE alias gains EPSS coverage with no per-source ingest
change. New data sources benefit automatically. The `EPSS` table schema is unchanged
and no provenance migration is needed.

Each call performs an index seek on `EPSS` directly (NVD source) or via
`VULNERABILITY_ALIAS` and then `EPSS` (non-NVD source). All columns involved are
indexed.

The resolution snippet is duplicated across read sites. Acceptable, as the logic is
stable and tied to this ADR.

Vulnerabilities with no CVE alias receive no EPSS. This is acceptable because EPSS is
defined per CVE.

[adr-014]: ./014-new-alias-schema.md
[epss]: https://www.first.org/epss/
[first-org]: https://www.first.org/
[^pg-with]: PostgreSQL docs, [WITH Queries](https://www.postgresql.org/docs/current/queries-with.html), §7.8.2.
