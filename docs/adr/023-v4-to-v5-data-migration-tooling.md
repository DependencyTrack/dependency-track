| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-05-14 | [@nscuro](https://github.com/nscuro) |

## Context

Dependency-Track v4 used DataNucleus to auto-generate its schema, and supported
H2, MySQL, MSSQL, and PostgreSQL. v5 only supports PostgreSQL, and manages its
schema with Flyway ([ADR-020]).

Existing v4 users need a way to bring their data forward. Telemetry shows[^1] that
roughly 80% of v4 deployments run on PostgreSQL, and 3% on MSSQL. MySQL was only
observed on a single instance. The rest runs on H2, which was never recommended for production.
We will support PostgreSQL and MSSQL as migration sources. H2 is out of scope.

The two source databases differ in types, identifier quoting, paging syntax,
and timestamp semantics. The tool has to handle both.

v4 datasets can be large, with some deployments exceeding 100 GB, so a
streaming, in-memory approach is not viable. The migration also has to survive
partial failures without restarting from zero on every error.

The migration is lossy in places. User records from `MANAGEDUSER`, `LDAPUSER`,
and `OIDCUSER` are consolidated into a single `USER` table ([ADR-006]).
Metrics are subject to a retention cutoff. Some unique constraints require
deduplication and conflict resolution. v4 also accumulated orphaned rows that
v5's stricter constraints would reject.

The tool is a one-off, run once per deployment during the upgrade. Correctness
on that single run is what matters. Long-term maintainability is out of scope.

## Decision

We will ship a self-contained CLI in `support/v4-migrator`. It depends only on
the existing `migration` module (to apply the v5 Flyway schema), picocli, JDBI,
Logback, and the official PostgreSQL and MSSQL JDBC drivers. It ships
as a single shaded executable jar and a container image bundling that jar.

### Pipeline

The pipeline follows the standard [ETL] model, with extract, transform, and
load as separate phases backed by persisted intermediate state. This is the
same separation of concerns used by any non-trivial data migration, and
operators are likely to recognise it from other tooling.

State is kept in a dedicated `staging` schema on the target PostgreSQL cluster.
All staging tables are `UNLOGGED`. The source of truth remains v4 until load
completes, so WAL is not needed.

A `migration_state` table tracks per-table progress across phases. A
`migration_config` table carries derived values that later phases need (for
example the metrics retention cutoff used for partition pre-creation). The CLI
exposes `bootstrap`, `extract`, `transform`, `load`, `verify`, `cleanup`, and a
convenience `run` that chains the three middle phases.

The `run` command accepts a `--sample` flag that caps rows per table for
rehearsals. A `--dry-run` flag prints the plan without touching either database.

`bootstrap` applies the v5 Flyway schema, pinned to head version `202605111028`.
Preflight refuses to operate against any other head. It also covers a number of
other prerequisites: PostgreSQL version, required extensions (`pg_trgm`), an
empty target check, recommended PostgreSQL settings, source schema markers, and
free-disk headroom for staging.

### Why target-side staging

We considered staging the intermediate state in an on-disk artifact format
(JSONL+zstd, SQLite, DuckDB, Parquet). We chose target-side `UNLOGGED` tables
instead, for the following reasons:

* One type system end to end. Source rows land in PostgreSQL once, and are never
  re-coerced.
* In-server `INSERT ... SELECT` is the fastest physically available load path.
* PostgreSQL already handles spilling and memory well. No second storage engine
  to tune.
* No new runtime dependencies beyond JDBC drivers.
* The intermediate state is inspectable mid-flight with `psql`.
* Per-batch commits give us extract-phase resumability for free.

The trade-off is disk. The target needs roughly 2x the final dataset size
during migration. Operators who want to migrate on dedicated hardware can
`pg_dump` and `pg_restore` the v5 schema afterwards. This is a documented,
supported workflow.

### Table registry

Each migrated table is declared once as a `TableMigration` record in a central
`TableRegistry`. A record carries up to four artefacts:

1. A DDL for the `src_*` staging table, typed to match the source.
2. An extract SELECT against v4.
3. A multi-statement SQL transform that builds a `tgt_*` table with v5-native
   types and semantics.
4. A load `INSERT ... SELECT` into the v5 schema.

Tables that only feed downstream consolidation (e.g. `MANAGEDUSER` into the
consolidated `USER`) omit the load step. Tables that are pure derivations of
others omit the extract step. The registry is the single source of truth for
table-level shape, ordering, and FK dependencies.

### Extract

Source flavour is detected from the JDBC URL.

PostgreSQL sources use the native binary `COPY` protocol. `COPY (SELECT ...) TO
STDOUT WITH (FORMAT BINARY)` on the source is piped directly into `COPY ... FROM
STDIN WITH (FORMAT BINARY)` on the target. No per-row coercion in Java.

MSSQL sources use a server-side cursor with JDBC batched inserts. Type
adaptation is explicit at this boundary. `DATETIME2` values are timezone-free,
and are reinterpreted as UTC for `timestamptz` by binding a UTC `Calendar` to
`getTimestamp` and `setTimestamp`. `BIT` becomes boolean. Binary types
(`BINARY`, `VARBINARY`, `LONGVARBINARY`, `BLOB`, `IMAGE`) become `bytea`.
`LIMIT` is rewritten to `SELECT TOP N` for `--sample`.

### Transform

Transforms run inside the target, as SQL. They read from `src_*` and write
`tgt_*`. This avoids a second coercion layer, and lets PostgreSQL's planner do
the heavy lifting.

The registry ships multi-statement scripts. A small splitter handles top-level
semicolons while respecting line comments, block comments, single and double
quoting, and dollar-quoted bodies. We do not need to contort transforms into
one statement per record.

Historical structures that were added and later dropped (the `ROLE` family from
Liquibase v5.6.0-28 dropped in v5.7.0-65, the `ADVISORY` and `CSAF_*` tables
from v5.7.0-18 dropped in v5.7.0-77, and others) are simply absent from the
registry. They are never extracted, never transformed, never loaded.

Lossy transformations from the collapsed changelog live here too:

* `USER` consolidation with `-CONFLICT-LDAP` and `-CONFLICT-OIDC` suffix
  resolution ([ADR-006]).
* Metrics retention cutoff applied to `PROJECTMETRICS` and `DEPENDENCYMETRICS`.
* `VULNERABLESOFTWARE` orphan filtering against the junction table.
* Disabling all `NOTIFICATIONRULE` rows whose `PUBLISHER_CONFIG` was migrated
  (Liquibase v5.7.0-36).
* `PERMISSION` handling: the migrator seeds the full v5 catalog (from the
  apiserver's `Permissions` enum at the pinned Flyway head) and builds
  `permission_name_map` by inner-joining v4 NAME against v5 PERMISSION.
  v4-only names like `VIEW_BADGES` drop out, silently removing any user or
  team assignment to them. v4's `ACCESS_MANAGEMENT` carried implicit
  portfolio-access-control bypass. v5 split that into the explicit
  `PORTFOLIO_ACCESS_CONTROL_BYPASS` permission (Liquibase v5.6.0-31). The
  migrator fans v4 `ACCESS_MANAGEMENT` holders out to `PORTFOLIO_ACCESS_CONTROL_BYPASS`
  in both `USERS_PERMISSIONS` and `TEAMS_PERMISSIONS` to preserve v4 behavior.

Probe tables capture data that is excluded from `tgt_*`. `probe_invalid_uuids`
for malformed identifiers. `probe_skipped_users` for v4 rows that violate v5's
NOT NULL on `USERNAME`. `probe_case_collisions` for cross-vendor case-insensitive
unique-key clashes. Probes are surfaced by `verify`.

### Load

Load runs `INSERT ... SELECT` from each `tgt_*` into its v5 destination, in a
FK-respecting order taken from the registry.

All user-defined triggers on `PROJECT` and on the normally write-blocked
`PROJECT_ACCESS_USERS` are disabled for the duration of load, then re-enabled.
Identity sequences are advanced past the loaded maxima with `setval`.

The partitioned metrics tables (`PROJECTMETRICS` and `DEPENDENCYMETRICS`) get
daily range partitions pre-created from the retention cutoff through tomorrow. Partition creation is chunked across
transactions to respect `max_locks_per_transaction`.

After load, the tool runs `ANALYZE` on every loaded table and refreshes
`PORTFOLIOMETRICS_GLOBAL`. It also replays the no-op-on-fresh-install delete
statements from v5.7.0 cleanup changesets, so migrated `CONFIGPROPERTY` and
`PERMISSION` rows match those of a fresh install.

Constraints are never deferred. Transforms are written to satisfy them up
front, so any violation that does occur points to a real bug rather than a
deferred surprise.

### Resumability

Re-running `extract` truncates `src_*` tables, drops all downstream `tgt_*`
tables, truncates probes, and clears transform and load ledger entries.
Re-running `transform` invalidates load state. Both are safe to retry.

`load` itself is not automatically resumable. A failed load needs inspection,
manual cleanup of partial v5 data, and a re-run. Intra-load resumability would
add complexity disproportionate to a one-shot tool. We accept the trade-off,
and document it.

### Verify

`verify` is advisory and non-fatal. It re-checks the Flyway head, compares
`src_*` to v5 row counts, summarises probe contents, and spot-checks a few
FK and UNIQUE constraints. It exits cleanly even on warnings. The operator is
expected to read the output and decide.

### Testing

End-to-end tests use Testcontainers. Each scenario spins up a v4 source
(PostgreSQL or MSSQL) and a v5 target, seeds representative v4 rows, runs the
pipeline, and asserts on v5 state.

The suite covers deduplication, user consolidation, orphan filtering, metrics
retention and partitioning, policy and notification rule migration, project
hierarchy, identity sequence advancement, preflight checks, and the dry-run
and sample modes. MSSQL parity tests cover the type-adaptation surface.

The default Surefire run excludes ITs. An opt-in `-Pe2e-tests` profile includes
them.

### AI-driven implementation

We will author the implementation in `support/v4-migrator`, primarily with AI
assistance, under continuous human supervision. Design decisions, review gates,
and corrections remain with a human at every step.

We choose this approach for this module only. The reasons are specific:

* The tool is single-use. It runs once per deployment and is decommissioned
  shortly after the upgrade window closes. The usual long-term arguments
  against generated code (drift, comprehension, refactor cost) do not apply.
* The work is mechanically large but shallow. Roughly 80 tables, two source
  dialects, and dozens of historical changesets produce a registry that is
  long and repetitive. Each entry is small. This shape suits machine authoring
  with per-entry human review.
* Correctness is bounded and verifiable. The pipeline either produces a v5
  database that matches the source under the documented rules, or it does not.
  The IT suite checks this directly against real PostgreSQL and MSSQL
  containers. We do not rely on subjective code-quality signals.
* Blast radius is contained. The tool runs against a target database the
  operator controls. Worst case, the operator drops the target and re-runs.

This decision is scoped to `support/v4-migrator`. It is not a general policy
for the project. The rest of the codebase continues under the standard
human-authored review process.

## Consequences

Users get one supported migration surface, a pinned target schema version that
fails fast on mismatch, and a documented downtime model. The staging schema is
inspectable mid-flight, which makes incident response on a failed migration
tractable. The tool ships as a single shaded jar and container image.

Operators must provision target disk for roughly 2x the dataset, and accept
that the migration is offline. Resumability stops at the phase boundary.
Load failures need manual cleanup before retry.

Some historical schema steps are deliberately skipped rather than replayed.
This avoids running transformations whose outputs were later dropped. The
registry does not map one-to-one onto the Liquibase and Flyway changelogs.

The registry should be read as data rather than hand-curated code. Reviewers should
focus on per-table correctness (extract SQL, transform SQL, load SQL, and the
matching IT) rather than on stylistic cohesion across entries. After v5 GA plus
a short deprecation window, the module is expected to be removed wholesale
rather than maintained.

[^1]: https://github.com/DependencyTrack/community/blob/main/community-meetings/2026-01-07.pdf
[ADR-006]: ./006-consolidate-user-tables.md
[ADR-020]: ./020-flyway-migrations.md
[ETL]: https://en.wikipedia.org/wiki/Extract,_transform,_load
