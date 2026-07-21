| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-07-21 | [@nscuro](https://github.com/nscuro) |

## Context

Dependency-Track resolves package metadata (latest version, publish timestamps, hashes) per Package
URL (PURL) from upstream repositories. [ADR 015](./015-package-metadata.md) covers the feature and
[ADR 021](./021-package-metadata-conditional-revalidation.md) covers how resolvers avoid redundant
requests. A singleton sweep workflow finds PURLs that are due and resolves them. A shared dependency
like `log4j` occurs in thousands of `COMPONENT` rows but has one metadata record, so the sweep resolves
each distinct PURL once per pass.

The original design had no state table. It derived what was due from what already existed: it scanned
`COMPONENT` and kept a PURL when no fresh metadata record existed for it. This caused three problems in
production:

* **Malformed PURLs were re-selected forever.** Some components carry a PURL that parses on import but
  fails to parse when read back. The negative cache was keyed on a parsed PURL, so these strings never
  got a record. Every sweep re-selected them and re-logged a warning. See [issue 6654][gh-6654].
* **The candidate query cost scaled with the whole portfolio.** `COMPONENT` holds one row per project per
  component, so it can hold millions of rows, and the same PURL is visited once per project. A
  steady-state sweep, where nothing is due, still paid the full cost to confirm there was no work.
* **The scan could exceed the activity lock timeout.** On large instances the scan ran past the
  one-minute lock, a second worker took over, and the workflow rescheduled itself without end. One
  report saw this run for a month. See [issue 6771][gh-6771].

The sweep is triggered on a daily schedule, after every BOM upload, and after every manual re-analysis,
so the expensive scan ran often, not once a day. Note that the singleton property prevents duplicate runs.

Any fix must respect the following constraints:

* The database is PostgreSQL, so write churn and index bloat must stay bounded and vacuum-manageable,
  and must not scale with how often the sweep is triggered.
* We prefer to derive work from existing state over an explicit work queue, which adds per-item inserts,
  deletes, and polling.

### Possible Solutions

#### A: Bound and resume the COMPONENT scan

Add a negative-cache table so every attempt leaves a record, including one for malformed PURLs.
Keep scanning `COMPONENT`, but scan a bounded window per activity call and resume with a keyset cursor.

*Pro*:

1. Fixes the malformed PURLs and the lock timeout without a derived table to keep in sync.
2. Keeps the existing candidacy source, so no seeding contract on the write paths.

*Con*:

1. A steady-state sweep still reads the whole portfolio in pieces to confirm nothing is due,
   so the cost problem remains.

#### B: Drive candidacy from a per-PURL state table

Add a state table keyed by the raw PURL string, seeded by the component write paths,
and derive candidacy from it instead of from `COMPONENT`.

*Pro*:

1. The table size follows the number of distinct PURLs, not components, so the sweep scans one row per PURL.
2. Malformed PURLs get a durable record, so they are no longer re-selected forever.
3. The sweep can finish in one call, well within the activity lock.

*Con*:

1. Adds a seeding contract on the component write paths.
2. Adds a derived table that must stay in sync with `COMPONENT`.

#### C: Add an explicit work queue

Maintain a queue of PURLs to resolve in a dedicated table.

*Pro*:

1. Candidacy is explicit, so the sweep never scans `COMPONENT`.

*Con*:

1. Mass expiry, where a sweep worth of PURLs becomes due every 24 hours, inserts and later deletes a
   full wave of queue rows each cycle. That is frequent birth-and-death churn on top of the resolution
   writes themselves.
2. Runs against our goal to derive work from existing state.

#### D: Track state on the existing metadata tables

Add the state to `PACKAGE_METADATA` or `PACKAGE_ARTIFACT_METADATA` instead of a new table.

*Pro*:

1. No new table.

*Con*:

1. The tables hold rows only for PURLs that resolved to metadata, but the problem PURLs are the ones
   with *none*, i.e. never attempted, not found upstream, or malformed. Giving them state means writing
   placeholder rows with no metadata, which readers would treat as real metadata.
2. The tables are read by primary key. Candidacy has to filter on a resolution timestamp, and an indexed
   timestamp that every re-resolution rewrites blocks the in-place ([HOT][pg-hot]) updates these tables
   want, and blocks tuning them as pure point-read tables (see [Storage layout](#storage-layout)).

## Decision

We will adopt solution **B**. We add a `PACKAGE_METADATA_RESOLUTION` table, keyed by the raw PURL
string, and derive candidacy from it. This gives malformed PURLs a durable record and resolves
[issue 6654][gh-6654]. The table has one row per distinct PURL:

| Column              | Type          | Notes                                                                                    |
|:--------------------|:--------------|:-----------------------------------------------------------------------------------------|
| `PURL`              | `TEXT`        | Primary key, the raw PURL string                                                         |
| `STATUS`            | `TEXT`        | One of the states below, `CHECK`-constrained                                             |
| `LAST_ATTEMPTED_AT` | `TIMESTAMPTZ` | `'epoch'` sentinel until the first attempt, never `NULL`. Covered by the composite candidacy index, see [Storage Layout](#storage-layout) |

`STATUS` records one state per PURL:

| State          | Meaning                        | Re-attempted?                              |
|:---------------|:-------------------------------|:-------------------------------------------|
| `PENDING`      | Seeded but never attempted     | Yes, immediately                           |
| `RESOLVED`     | Metadata found                 | Yes, once past the 24 h time-to-live (TTL) |
| `NOT_FOUND`    | No metadata upstream           | Yes, once past the 24h TTL                 |
| `UNRESOLVABLE` | Malformed PURL, cannot resolve | No, suppressed forever                     |

### Candidacy

* A PURL is a candidate when it is due. Due means `LAST_ATTEMPTED_AT` is older than the TTL.
  Never-attempted rows sit at the `'epoch'` sentinel, so they are always due.
* Candidacy deliberately does not check whether the PURL still exists in `COMPONENT`.
  Such a check would make the cost of one candidate batch grow with the number of orphan rows.
  After a large deletion, a single batch could then again exceed the activity lock,
  which is the failure mode of [issue 6771][gh-6771]. Skipping the check keeps the batch cost
  bounded by the batch size alone. The price is small: an orphan row is resolved at most once
  more before the maintenance task removes it.
* The candidate query returns one batch per call and is keyset-paginated, so the workflow resolves a
  batch and then continues until no more are due. [Storage layout](#storage-layout) covers the index and
  ordering that keep each batch cheap and let a steady-state sweep finish within the activity lock, which
  resolves [issue 6771][gh-6771].
* Orphan rows, where no component uses the PURL any more, are removed by the package metadata
  maintenance task.

### Seeding

The component write paths keep the table seeded, atomically with the component writes:

* A BOM import seeds all of the project's PURLs in one statement at the end of its transaction.
  The component create / update REST endpoints seed the affected PURL inside theirs.
* Seeding uses `INSERT ... ON CONFLICT DO NOTHING`, so it writes no dead tuples, is idempotent,
  and never resets an already-resolved PURL. The sweep stays the only writer of outcomes,
  so the single-resolver guarantee holds.

We do not seed using database triggers. Components are written row by row during BOM import,
so per-statement triggers from two imports adding the same new PURLs in different order could deadlock.
One bulk insert per import, rows ordered by PURL, gives every importer the same lock order.

### Storage layout

Every sweep selects the rows due for resolution, those with `LAST_ATTEMPTED_AT` past the TTL.
This due-predicate runs on every trigger, so it is the table's dominant access pattern.

We serve it with a composite partial index on `(LAST_ATTEMPTED_AT, PURL)`, restricted to exclude the
permanently-suppressed `UNRESOLVABLE` rows. The candidate query orders and keyset-paginates by that same
pair, so one index covers both the due-predicate and the pagination order. The cost then scales with the
number of due rows, not the table size. An empty sweep reads a handful of index pages instead of the whole
table, and the daily expiry wave drains along the index in order.

Both the ordering and the sentinel are deliberate:

* We order by that pair rather than by the primary key. Under `ORDER BY ... LIMIT`, PostgreSQL would
  otherwise walk the primary key to satisfy the order and apply the due-predicate as a filter, which scans
  the whole table on an empty sweep and never touches a `LAST_ATTEMPTED_AT`-only index.
* We give never-attempted rows the `'epoch'` sentinel instead of `NULL`, so the due-predicate stays a
  single `<=` range. A `LAST_ATTEMPTED_AT IS NULL OR <= ...` disjunction would not map to a clean index
  range, so it would defeat the same plan.

The trade-off is that re-resolution updates the indexed timestamp, so it is not an in-place (HOT) update.
We accept this. The read runs on every workflow trigger, far more often than the once-per-PURL-per-TTL write,
so the read is the operation to optimize. That write is the re-resolution the feature performs regardless of
design, not churn this design adds, and it stays bounded: one write per PURL per TTL over a fixed set of
rows. The dead-tuple rate scales with the number of distinct PURLs, not with the portfolio, so it is far
below the component count and stays vacuum-manageable.

Aggressive [autovacuum][pg-autovacuum] configured on this table reclaims the heap churn.
The timestamp only ever grows, and PostgreSQL 14 (our baseline version) keeps its index
in check with [bottom-up index deletion][pg-btree-deletion] on repeated non-HOT updates.

The metadata tables make the opposite choice. Previously their `RESOLVED_AT` column was indexed,
because the old candidacy derivation queried metadata freshness.
Moving candidacy to `PACKAGE_METADATA_RESOLUTION` removes that reason,
so this change drops the `RESOLVED_AT` index on both metadata tables, and they update in place (HOT).

### Reconciliation

Candidacy is read only from this table, so a missing row silently means a PURL is never resolved.

The write paths and upgrade backfill cover the normal flows, but rows can still go missing,
through a narrow race with the orphan cleanup or through operator actions such as a replication restore.
The maintenance task therefore seeds a `PENDING` row for every component PURL that has none,
using `INSERT ... ON CONFLICT DO NOTHING`. Running right after the orphan cleanup,
it heals that race and bounds any gap to one maintenance interval.

## Consequences

* **Steady-state sweeps are cheap regardless of trigger frequency.** The indexed due-predicate lets an
  empty or near-empty sweep return from a handful of index pages instead of paging the whole `COMPONENT`
  table across many workflow steps, so it no longer matters that the sweep fires on every upload.
  Freshly imported PURLs resolve sooner through their seeded rows.
* **Re-resolution writes are not HOT.** Indexing `LAST_ATTEMPTED_AT` means each re-resolution writes a
  new row version and index entries rather than updating in place. This is the deliberate cost of the
  cheap read. The churn is one write per PURL per time-to-live, bounded and reclaimed by autovacuum, and
  far smaller than the read I/O it removes on a large portfolio.
* **Malformed PURLs no longer loop or spam logs.** No metadata rows are written for empty or malformed
  results. Readers are unaffected: they already treat an absent row like an all-empty row.
* **Seeding is a contract.** Every write path that introduces a new component PURL must seed the table.
  A forgotten path delays resolution by up to the reconciliation interval, not permanently.
* **`UNRESOLVABLE` has no automatic escape.** If PURL parsing is later relaxed or upstream data
  corrected, those rows stay suppressed until something re-writes the PURL or an operator clears the row.
* **Reconciliation reintroduces a periodic `COMPONENT` scan.** It runs on the maintenance schedule,
  not every trigger, in keyset-paginated batches. Rows are almost always present,
  so it inserts close to nothing in steady-state.
* **Orphan PURLs can be resolved once more than needed.** Between the deletion of a PURL's last
  component and the next maintenance run, its due row is still swept. This wastes at most one
  resolution per orphan PURL. We accept this to keep the candidate batch cost bounded.
* **A PURL that leaves and later re-enters the portfolio is churned like a queue row.** The orphan
  cleanup deletes its row, and a later import or reconciliation re-seeds it as `PENDING`.
  This is the birth-and-death churn solution C was rejected for, but it needs the PURL to disappear from every
  project at once, not just churn within one import, so it is expected to be rare.
* **Upgrade backfills once.** Already-resolved PURLs keep their state and TTL, so the first sweep does
  not re-resolve the whole portfolio. The backfill scans `COMPONENT` once.
* **In-flight sweeps can fail on upgrade.** The sweep workflow and its candidate-fetch activity now take
  an argument where they previously took none, so a run mid-flight at upgrade time can fail on replay
  against its recorded history. We accept this: the workflow is re-created after every BOM upload and daily,
  so a failed run is superseded within one cycle.

[gh-6654]: https://github.com/DependencyTrack/dependency-track/issues/6654
[gh-6771]: https://github.com/DependencyTrack/dependency-track/issues/6771
[pg-hot]: https://www.postgresql.org/docs/current/storage-hot.html
[pg-autovacuum]: https://www.postgresql.org/docs/current/routine-vacuuming.html#AUTOVACUUM
[pg-btree-deletion]: https://www.postgresql.org/docs/current/btree.html#BTREE-DELETION
