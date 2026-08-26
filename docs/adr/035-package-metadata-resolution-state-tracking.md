| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-07-21 | [@nscuro](https://github.com/nscuro) |

## Context

Dependency-Track resolves package metadata (latest version, publish timestamps, hashes) per Package
URL (PURL) from upstream repositories. [ADR 015](./015-package-metadata.md) covers the feature.
[ADR 021](./021-package-metadata-conditional-revalidation.md) covers how resolvers avoid redundant
requests. A singleton workflow finds the PURLs that are due and resolves them. A shared dependency
appears in thousands of `COMPONENT` rows but has one metadata record. Each distinct PURL is therefore
resolved once per run.

The original design had no state table. It derived what was due from what already existed. It scanned
`COMPONENT` and kept a PURL when no fresh metadata record existed for it. This caused the following issues:

* **Malformed PURLs were selected forever.** Some components carry a PURL that parses on import but
  fails to parse when read back. The negative cache was keyed on a parsed PURL. These strings never
  got a record. Every run selected them again and logged the same warning. See [issue 6654].
* **The candidate query cost scaled with the portfolio.** `COMPONENT` holds one row per project per
  component. It can hold millions of rows, and the same PURL is visited once per project.
  Even a run with nothing due paid the full cost to confirm there was no work.
* **The scan could exceed the lock timeout.** On large instances the scan ran past the one-minute
  lock. A second worker took over, and the workflow rescheduled itself without end.
  One report saw this run for a month. See [issue 6771].

The workflow is triggered daily, after every BOM upload, and after every manual re-analysis.
The expensive scan therefore ran often, not once a day. The singleton property prevents duplicate runs.

Important constraints:

* The database is PostgreSQL, so write churn and index bloat must stay bounded.
* They must not grow with how often the workflow is triggered.
* We prefer to derive work from existing state over an explicit work queue,
  which adds per-item inserts, deletes, and polling.

### Possible Solutions

#### A: Bound and resume the COMPONENT scan

Add a negative-cache table. Every attempt then leaves a record, including one for malformed PURLs.
Keep scanning `COMPONENT`, but scan a bounded window per activity call and resume with a keyset cursor.

*Pro*:

1. Fixes the malformed PURLs and the lock timeout. No derived table to keep in sync.
2. Keeps deriving candidates from `COMPONENT`. The write paths need no seeding contract.

*Con*:

1. A run still reads the whole portfolio in pieces to confirm nothing is due. The cost problem remains.

#### B: Drive candidacy from a per-PURL state table

Add a state table keyed by the raw PURL string. Seed it from the component write paths. 
Derive candidacy from it instead of from `COMPONENT`.

*Pro*:

1. The table holds one row per distinct PURL, not one per component. A run scans far fewer rows.
2. Malformed PURLs get a durable record. They are no longer selected forever.
3. A run finishes a batch well within the lock timeout.

*Con*:

1. Adds a seeding contract on the component write paths.
2. Adds a derived table that must stay in sync with `COMPONENT`.

#### C: Add an explicit work queue

Maintain a queue of PURLs to resolve in a dedicated table.

*Pro*:

1. Candidacy is explicit. A run never scans `COMPONENT`.

*Con*:

1. Every PURL becomes due again every 24h. Each cycle therefore inserts a wave of queue rows and
   later deletes them. That churn comes on top of the resolution writes themselves.
2. Runs against our goal to derive work from existing state.

#### D: Track state on the existing metadata tables

Add the state to `PACKAGE_METADATA` or `PACKAGE_ARTIFACT_METADATA` instead of a new table.

*Pro*:

1. No new table.

*Con*:

1. These tables hold rows only for PURLs that resolved to metadata. The problem PURLs are the ones
   with *none*: never attempted, not found upstream, or malformed. Giving them state means writing
   placeholder rows, which readers would treat as real metadata.
2. These tables are read by primary key. Candidacy has to filter on a resolution timestamp.
   Indexing that timestamp would stop them from being tuned as pure point-read tables.

## Decision

We will adopt solution **B**. We add a `PACKAGE_METADATA_RESOLUTION` table, keyed by the raw PURL
string, and derive candidacy from it. A malformed PURL now gets a row like any other, which resolves
[issue 6654]. The table has one row per distinct PURL:

| Column              | Type          | Notes                                                    |
|:--------------------|:--------------|:---------------------------------------------------------|
| `PURL`              | `TEXT`        | Primary key, the raw PURL string                         |
| `STATUS`            | `TEXT`        | One of the states below, `CHECK`-constrained             |
| `LAST_ATTEMPTED_AT` | `TIMESTAMPTZ` | `'epoch'` sentinel until the first attempt, never `NULL` |

A PURL becomes due again after a time-to-live (TTL) of 24h.

| State          | Meaning                        | Re-attempted?          |
|:---------------|:-------------------------------|:-----------------------|
| `PENDING`      | Seeded but never attempted     | Yes, immediately       |
| `RESOLVED`     | Metadata found                 | Yes, once past the TTL |
| `NOT_FOUND`    | No metadata upstream           | Yes, once past the TTL |
| `UNRESOLVABLE` | Malformed PURL, cannot resolve | No, suppressed forever |

### Candidacy

A PURL is a candidate when `LAST_ATTEMPTED_AT` is older than the TTL. Never-attempted rows sit at the
`'epoch'` sentinel, so they are always due. The candidate query returns one batch per call and is
keyset-paginated. The workflow resolves a batch, then continues until no more are due.
A batch is bounded work, so it fits within the lock timeout. That resolves [issue 6771].

The query does not check whether the PURL still exists in `COMPONENT`. That check would make the cost
of one batch grow with the number of orphan rows. A single batch could then exceed the lock timeout
again after a large deletion. Leaving the check out bounds batch cost by the batch size alone.

### Seeding

The component write paths keep the table seeded, in the same transaction as the component writes.
A BOM import seeds all of the project's PURLs in one statement. The component create and update REST
endpoints seed the affected PURL. Seeding uses `INSERT ... ON CONFLICT DO NOTHING`. It is idempotent,
writes no dead tuples, and never resets an already-resolved PURL. The workflow stays the only writer
of outcomes.

We do not seed with database triggers. Components are written row by row during BOM import. Two imports
adding the same new PURLs in different order could deadlock on per-statement triggers. One bulk insert
per import, with rows ordered by PURL, gives every importer the same lock order.

### Storage layout

The candidate query runs on every trigger. It is the table's dominant access pattern. We serve it with
a composite partial index on `(LAST_ATTEMPTED_AT, PURL)` that excludes the suppressed `UNRESOLVABLE`
rows. The query orders and paginates by that same pair, so one index covers both. Cost then scales with
the number of due rows, not the table size. A run with nothing due reads a handful of index pages.
The daily expiry wave drains along the index in order.

Both the ordering and the sentinel are deliberate. Ordering by the primary key would make PostgreSQL
walk that key and apply the due condition as a filter. That scans the whole table when nothing is due.
Using `NULL` in place of the `'epoch'` sentinel would split the condition in two. The result maps to no
clean index range and defeats the same plan.

Indexing the timestamp has a cost. Re-resolution rewrites it, so the update is not in-place
([HOT][pg-hot]). We accept that. The read runs on every trigger, the write only once per PURL per TTL,
so the read is the one to optimize. That write also happens regardless of design, because it is the
re-resolution itself. Its rate follows the number of distinct PURLs, not the portfolio.
Aggressive [autovacuum] on this table reclaims the heap churn. PostgreSQL 14, our baseline version,
keeps the index in check with [bottom-up index deletion][pg-btree-deletion].

The metadata tables make the opposite choice. Their `RESOLVED_AT` column was indexed because the old
design derived candidates from metadata freshness. That reason is gone. This change drops the index on
both tables, and they update in place.

### Reconciliation

Candidates are read only from this table. A PURL without a row is therefore never resolved,
and nothing reports it. The write paths and the upgrade backfill cover the normal flows.
Rows can still go missing through a narrow race with the orphan cleanup, or through operator
actions such as a replication restore. The package metadata maintenance task therefore seeds a `PENDING`
row for every component PURL that has none. It runs right after the orphan cleanup.
That heals the race and bounds any gap to one maintenance interval.

## Consequences

* **Runs are cheap regardless of trigger frequency.** A run no longer pages the whole `COMPONENT` table
  across many workflow steps, so triggering on every upload stops being a problem. Freshly imported
  PURLs also resolve sooner through their seeded rows.
* **Re-resolution writes are not HOT.** Each one writes a new row version and index entries instead of
  updating in place. This is new write churn, bounded by the number of distinct PURLs and reclaimed by
  autovacuum.
* **Malformed PURLs no longer loop or fill the log.** No metadata rows are written for empty or
  malformed results. Readers already treat an absent row like an all-empty row, so they are unaffected.
* **Seeding is a contract.** Every write path that introduces a new component PURL must seed the table.
  A forgotten path delays resolution by up to one reconciliation interval. It does not delay it permanently.
* **`UNRESOLVABLE` has no automatic escape.** PURL parsing may later be relaxed, or upstream data
  corrected. Those rows stay suppressed until something rewrites the PURL, or an operator clears the row.
* **Reconciliation reintroduces a periodic `COMPONENT` scan.** It runs on the maintenance schedule,
  not on every trigger. Rows it inserts stop qualifying as missing, so each batch makes progress
  without a cursor. Rows are almost always present, so a run normally stops after one empty batch.
* **Orphan PURLs cost a little.** A PURL whose last component was deleted stays due until the next
  maintenance run, so it is resolved once more than needed. If it later re-enters the portfolio,
  the cleanup and a following import churn its row the way solution C was rejected for. Both are cheap.
  The second needs the PURL to disappear from every project at once, so we expect it to be rare.
* **Upgrade backfills once.** Already-resolved PURLs keep their state and TTL. The first run after the
  upgrade does not re-resolve the whole portfolio. The backfill scans `COMPONENT` once.
* **In-flight runs can fail on upgrade.** The workflow and its candidate-fetch activity now take an
  argument where they previously took none. A run in flight at upgrade time can fail on replay against
  its recorded history. We accept that. The workflow is re-created daily and after every BOM upload,
  so a failed run is superseded within one cycle.

[issue 6654]: https://github.com/DependencyTrack/dependency-track/issues/6654
[issue 6771]: https://github.com/DependencyTrack/dependency-track/issues/6771
[pg-hot]: https://www.postgresql.org/docs/current/storage-hot.html
[autovacuum]: https://www.postgresql.org/docs/current/routine-vacuuming.html#AUTOVACUUM
[pg-btree-deletion]: https://www.postgresql.org/docs/current/btree.html#BTREE-DELETION
