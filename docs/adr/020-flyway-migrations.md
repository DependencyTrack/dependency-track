| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-05-02 | [@nscuro](https://github.com/nscuro) |

## Context

Schema migrations were managed with Liquibase. The 4.x line is Apache-2.0,
but the [5.0 release](https://docs.liquibase.com/community/release-notes/5-0)
relicensed the project under a non-OSS license, and the
[support window for the 4.x line is unclear](https://github.com/liquibase/liquibase/issues/7375).
The project requires its full runtime dependency set to remain OSS,
so staying on Liquibase past 4.x is not a viable long-term path.

In parallel, the Liquibase changelog has grown to several hundred
changesets across multiple per-version XML files, plus a handful of custom
Java change classes for transformations the XML DSL could not express. None
of those one-shot transformations were relevant to fresh installations any
longer, and the volume of historical changesets has become a friction point
for contributors authoring new ones.

The project has not yet reached its GA release, so existing production
deployments are few and well known. This is the last reasonable opportunity
to collapse the changelog without requiring users to perform a multi-step
upgrade dance.

A change of tooling and a truncation of history are independently desirable.
Combining them avoids paying the cost of a coordinated schema reset twice.

## Decision

We will adopt [Flyway](https://github.com/flyway/flyway) as the migration tool.
Flyway is Apache-2.0 licensed, SQL-first, and the de facto alternative to
Liquibase in the JVM ecosystem.
Its model maps cleanly onto how the project already authored most of its
non-trivial changesets, which were raw SQL embedded in XML wrappers.

We will collapse the entire prior Liquibase changelog into a single
timestamped [baseline migration](https://documentation.red-gate.com/fd/baseline-migrations-273973336.html)
that creates the schema as it stands today.
A follow-up [versioned migration](https://documentation.red-gate.com/fd/versioned-migrations-273973333.html)
will drop the legacy Liquibase bookkeeping tables. Existing deployments
adopt the baseline transparently through Flyway's baseline-on-migrate
behaviour, then converge with fresh deployments after the cleanup migration
runs.

Stored procedures, functions, and views move from the project's homegrown
"reapply on content change" mechanism to Flyway's
[repeatable migrations](https://documentation.red-gate.com/fd/repeatable-migrations-273973335.html),
which provide the same semantics out of the box.

Standalone migration execution reuses the existing init-task framework. Setting
`dt.init-tasks.exit-after-completion=true` runs all init tasks, including `DatabaseMigrationInitTask`,
and exits before the HTTP server starts. No new CLI surface is added.

The custom Java change classes that backed Liquibase transformations are
removed. Their effects are already baked into the baseline, and Flyway's
Java migration support is not needed for any current or foreseen use case.

## Consequences

The project's runtime dependency set stays fully OSS, and the migration
authoring loop becomes simpler. New migrations are plain SQL files in a
single directory, named by timestamp, with no surrounding XML or per-release
index file to maintain. The dependency footprint shrinks, since Flyway
pulls in substantially less than Liquibase did, and one internal support
module is removed entirely.

Operators upgrading from a recent pre-GA release see no behavioural change.
Their existing schema is recognised as already at the baseline, the legacy
bookkeeping tables are dropped on the next migration run, and subsequent
migrations apply normally.

Historical changesets are no longer replayable. A developer cannot
reconstruct the schema's evolution by reading the migration directory alone,
and must consult git history for anything older than the baseline. We
consider this an acceptable cost given the changelog's prior volume and the
project's pre-GA status. After GA the same option will not be available
without a coordinated upgrade.

The Liquibase precondition and rollback DSLs are gone. Preconditions were
used sparingly, and rollbacks were never relied on in production. Future
migrations express conditional logic in plain SQL, and reversibility is
handled by writing forward-only compensating migrations.

Flyway enforces checksum validation on applied migrations, so versioned
files merged to the main branch are immutable. This was already the
convention under Liquibase, and is now mechanically enforced rather than
left to reviewer discipline.

Liquibase's `updateSQL` workflow, which produced a delta migration script for
operators to review or hand-apply under change control, has no Flyway OSS
equivalent and is not being replaced. Flyway's `dryRunOutput` is a Teams-only
feature in 12.4.0 and is not available in the OSS edition. We do not consider
this a meaningful loss: under Flyway, migrations are already plain SQL files
committed to the repository, so anyone wishing to inspect pending migrations
can read them directly from
[`migration/src/main/resources/org/dependencytrack/migration`](../../migration/src/main/resources/org/dependencytrack/migration)
in version order. Hand-applying that SQL out-of-band is discouraged regardless,
because it would not update Flyway's `flyway_schema_history` table and would
cause Flyway to attempt to re-apply the same migrations on the next run.
Operators wanting a controlled migration step should run the API server with
`dt.init-tasks.exit-after-completion=true` so migrations execute and history is recorded.
