| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-06-10 | [@nscuro](https://github.com/nscuro) |

## Context

`DEPENDENCYMETRICS` and `PROJECTMETRICS` are partitioned by `LAST_OCCURRENCE`.
Both tables carry `ON DELETE CASCADE` foreign keys to `COMPONENT` and `PROJECT`,
so deleting a parent also deletes its metric rows.

When a partition is dropped, PostgreSQL also drops the foreign key constraint that the partition inherited.
Dropping the constraint removes the action triggers on the referenced side,
which requires an `ACCESS EXCLUSIVE` lock on `COMPONENT` and `PROJECT`
(see [ALTER TABLE notes][pg-altertable], [lock modes][pg-locking]). Concurrent traffic holds weaker locks on
the same tables: `SELECT` takes `ACCESS SHARE`, and a metric `INSERT` takes `ACCESS SHARE` plus a row-level
`FOR KEY SHARE` while it validates the foreign key. `ACCESS EXCLUSIVE` conflicts with every other lock mode,
so the two sides can deadlock. PostgreSQL aborts the partition drop, and the maintenance task fails.
An occurrence of this was reported in [#6343].

The risk is real but small, because the maintenance task runs on startup and then on the cron `1 * * * *`.
The `update-portfolio-metrics` only writes a row for projects that do not yet have one for `$today`.
The `analyze-project` workflow writes a row at the end of each analysis, and the scheduled portfolio
analysis runs daily at 06:00 UTC by default. Most hours, the writers are quiet and the maintenance task
takes the lock without contention. The deadlock becomes likely only under sustained back-to-back BOM uploads,
where re-analysis keeps the writers busy for hours.

The foreign keys also cost in two other places:

1. A `DELETE` of a project must visit every metrics partition once per component,
   because the partition key is a date and PostgreSQL cannot prune by component or project ID.
2. Every metrics insert takes a read lock on `COMPONENT` and `PROJECT` for foreign key validation,
   which blocks exclusive locks taken by deletes.

Through the API, metrics rows are read only through a parent UUID.
If the parent is gone, the API returns `404` before it touches the metric tables.

`PORTFOLIOMETRICS_GLOBAL` inner-joins `PROJECT`, so orphan rows drop out at refresh.

No path in the application reads a metric row without first resolving its parent.

### Possible Solutions

#### A: Drop only `ON DELETE CASCADE`, keep the foreign keys

Change the constraints from `ON DELETE CASCADE` to `ON DELETE NO ACTION`.
Parent deletion no longer cascades into the metric tables.

*Pro*:

1. The application can still rely on the foreign key to reject metric inserts that race with a parent delete.

*Con*:

1. The action triggers on the referenced side still exist. Dropping a partition still needs `ACCESS EXCLUSIVE`
   on `COMPONENT` and `PROJECT`. The deadlock window from [#6343] stays open.
2. Project and component deletion now fails outright if metric rows still reference them. Cleanup must happen
   in application code before the parent delete, walking every partition.

#### B: Replace partition drop with `DELETE` for retention

Keep the foreign keys. Replace the per-partition `DROP TABLE` with a bulk
`DELETE FROM ... WHERE "LAST_OCCURRENCE" < cutoff`.

*Pro*:

1. No DDL, no constraint drop, no `ACCESS EXCLUSIVE` lock on the parent tables. The deadlock window closes.

*Con*:

1. Throws away the main benefit of partitioning. Bulk `DELETE` writes dead tuples that autovacuum must reclaim.
   Indexes grow rather than shrink.
2. Cascade chain on parent deletion still walks every partition. Same cost as today, with no upside.

#### C: Schedule the partition drop during a quiet window

Move the maintenance cron from `1 * * * *` to a known-quiet hour, like overnight.

*Pro*:

1. Smallest change.

*Con*:

1. Operational, not architectural. A deployment with users across multiple timezones has no globally quiet window.
   Scheduled BOM uploads and downstream ingestion can run at any hour.
2. Does not address the cost of cascading deletes on parent removal.

#### D: Drop the foreign keys

Drop the three constraints from `DEPENDENCYMETRICS` and `PROJECTMETRICS`.
Partition retention becomes the only mechanism that removes metric rows.

*Pro*:

1. The partition drop touches only the metric tables. No lock on `COMPONENT` or `PROJECT`.
2. Parent deletion becomes cheap, with no cross-partition cascade.
3. Metric inserts no longer compete with parent deletes on the row lock.

*Con*:

1. Orphan metric rows can outlive their parent until partition retention removes them.
2. A metric insert raced with a parent delete now produces an orphan instead of failing at commit.

## Decision

We will follow solution **D**. The three foreign keys from `DEPENDENCYMETRICS` and `PROJECTMETRICS` to `COMPONENT`
and `PROJECT` are dropped. The partition retention task becomes the only mechanism that removes metric rows.
Other tables that reference `COMPONENT` or `PROJECT` are out of scope.

## Consequences

The partition drop no longer needs an exclusive lock on `COMPONENT` or `PROJECT`.
The deadlock window closes. Deleting projects or components no longer cascades into the metric tables,
so deleting a large project becomes much faster. Metric inserts no longer validate against the parent tables,
so they stop competing with deletes for the lock.

Storage cost actually goes *down*. A cascading delete writes dead tuples into every metric partition that holds
a referenced row, and autovacuum has to reclaim them. Dropping a whole partition at retention reclaims the space
at once with no vacuum work.

Metric rows can outlive their parent. Orphans are not reachable from the API and self-clean when their partition is dropped.

A race between a metric insert and a parent delete now produces an orphan instead of an aborted insert.
We accept this.

Reversing the decision later is possible but not free. A re-added foreign key must use `ADD CONSTRAINT ... NOT VALID`
followed by `VALIDATE CONSTRAINT` to avoid the same exclusive lock that motivated this change.

`NOT VALID` takes the weaker `SHARE ROW EXCLUSIVE` lock on both tables, and `VALIDATE CONSTRAINT` only needs
`SHARE UPDATE EXCLUSIVE` on the referencing table, and `ROW SHARE` on the referenced one
(see [ALTER TABLE notes][pg-altertable]).

`VALIDATE CONSTRAINT` also fails as soon as it hits an orphan. A reversal must therefore purge orphans first,
with queries like `DELETE FROM "PROJECTMETRICS" WHERE "PROJECT_ID" NOT IN (SELECT "ID" FROM "PROJECT")`
and the corresponding statement for `DEPENDENCYMETRICS`. Each purge writes dead tuples that autovacuum must reclaim,
so the reversal is more disruptive than the original drop.

[#6343]: https://github.com/DependencyTrack/dependency-track/issues/6343
[pg-altertable]: https://www.postgresql.org/docs/current/sql-altertable.html#SQL-ALTERTABLE-NOTES
[pg-locking]: https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-TABLES
