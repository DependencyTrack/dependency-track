# Database Migrations

We manage DB schema changes with [Flyway](https://www.red-gate.com/products/flyway/).
The API server owns the schema and applies pending migrations at startup.

Migrations live in [`migration/src/main/resources/org/dependencytrack/migration`](../migration/src/main/resources/org/dependencytrack/migration)
and follow Flyway's naming convention:

* `V<timestamp>__<description>.sql` for versioned migrations, applied once in timestamp order.
  `<timestamp>` is `YYYYMMDDHHMM` (UTC).
* `R__<name>.sql` for repeatable migrations (stored procedures, functions, views).
  Reapplied automatically when their content changes.

## Adding a Migration

Scaffold a new versioned migration:

```shell
make new-migration NAME="add foo column to bar"
```

This creates an empty `V<timestamp>__add_foo_column_to_bar.sql` file. Add your DDL/DML to it.

For repeatable migrations, edit the relevant `R__*.sql` file directly, no new file needed.

> [!IMPORTANT]
> Do not modify versioned migrations already merged to `main`.
> Flyway rejects checksum mismatches on existing deployments.
> Add a new migration instead.

> [!NOTE]
> Migrations run with `outOfOrder=true` so they can be backported to patch branches
> without blocking the next minor upgrade. See [`RELEASING.md`](../RELEASING.md#4-flyway-migrations).

## Linting Migrations

New and modified migrations are linted with [squawk](https://squawkhq.com) to catch operationally
unsafe DDL (missing `CONCURRENTLY` on indexes, blocking locks, `NOT NULL` columns without defaults, etc.)
before they hit production deployments.

Run the linter locally:

```shell
make lint-migrations
```

The target only lints migrations changed relative to `BASE_REF`. It defaults to `upstream/main`
when an `upstream` remote exists, and to `origin/main` otherwise. Point it at another branch when
the change targets one, for example a patch release branch:

```shell
make lint-migrations BASE_REF=upstream/5.1.x
```

The same check runs in CI on every pull request via the `Lint Migrations` job in
[`ci-lint.yaml`](../.github/workflows/ci-lint.yaml). PRs that introduce squawk findings
will fail this job.

Suppress an individual finding only when justified, by annotating the SQL statement
(see [Disabling rules via comments](https://squawkhq.com/docs/cli#disabling-rules-via-comments)):

```sql
-- squawk-ignore <rule-name>
ALTER TABLE ...;
```

## Migrations and Transactions

Flyway wraps each migration script in a single transaction by default.
A few Postgres DDL statements *cannot run inside a transaction*, most notably:

* `CREATE INDEX CONCURRENTLY`
* `DROP INDEX CONCURRENTLY`
* `REINDEX CONCURRENTLY`
* `ALTER TYPE ... ADD VALUE`

Running them in the default transactional mode will fail.
Squawk may push you towards using these constructs, but it doesn't know about Flyway executing
migrations in transactions implicitly.

Disable the transaction wrapper for that specific migration by adding a sidecar configuration
file with the same name as the migration plus a `.conf` suffix, for example:

```text
V202606151200__add_foo_bar_idx.sql
V202606151200__add_foo_bar_idx.sql.conf
```

```properties
# V202606151200__add_foo_bar_idx.sql.conf
executeInTransaction=false
```

```sql
-- V202606151200__add_foo_bar_idx.sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS "FOO_BAR_IDX" ON "FOO" ("BAR");
```

See Flyway's [script configuration docs](https://documentation.red-gate.com/fd/script-configuration-277578847.html)
for the full list of per-script overrides.

> [!WARNING]
> When `executeInTransaction=false`, the migration is no longer atomic.
> Keep these files small and idempotent (e.g. `IF NOT EXISTS`) so a partial
> failure can be safely re-run.
