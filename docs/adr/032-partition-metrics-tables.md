| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-07-16 | [@nscuro](https://github.com/nscuro) |

> [!NOTE]
> This ADR was written retroactively. The decision was made and shipped before the project
> started its ADR practice, so it was never recorded. It is based on [hyades#1744],
> which initially reported the problem and proposed the change.

## Context

The `DEPENDENCYMETRICS` and `PROJECTMETRICS` tables hold a time series. Each row is a snapshot
of the vulnerability and policy violation counts for one component or one project.
Through version 4, both were plain tables without partitioning.

The application refreshed metrics every hour. The refresh walked every active project and every
component and recomputed the counts. When nothing had changed since the last refresh, it did not
add a row. Instead it updated the existing latest row and moved its `LAST_OCCURRENCE` timestamp
forward, to record that the values were still current. It added a new row only when the counts
were different. There was no retention. Rows were never removed based on age, so the history grew
without bound. The only deletes came from removing a project or component, which cascaded `DELETE`s
into the metrics tables.

PostgreSQL uses multi version concurrency control (MVCC). Under MVCC, an update does not change a
row in place, it writes a new version and marks the old one dead. Deletion also marks the row
dead. Dead rows stay on disk until autovacuum reclaims them.

Both write patterns were costly at scale:

* Moving the timestamp forward once per component and project every hour produced about 24 dead rows per
  subject per day, even when no count had changed.
* Cascading deletes on parent removal added more dead rows, and large deletes caused spikes in WAL traffic.
* Because there was no retention, the tables also grew without bound.

Over time they became the largest in the database by a wide margin. Autovacuum was busy on them constantly,
the tables and their indexes bloated, and query performance suffered.
These symptoms were reported and analysed in [hyades#1744].

Keeping the number of stored rows small favours updating one row in place. Keeping MVCC churn low
favours never updating a row at all. The version 4 design kept the row count small and paid for it
with a high volume of updates.

### Possible Solutions

#### A: Keep the plain tables and tune autovacuum

Leave the schema and the write pattern as they are. Make autovacuum run more often and add scheduled vacuum jobs.

*Pro*:

1. No schema change is needed. The stored row count stays small.

*Con*:

1. It does not remove the cause. The churn grows with the size of the portfolio and the refresh rate,
   so autovacuum can never keep up as data grows.
2. Bounding growth still needs a bulk `DELETE` for retention, so it keeps producing dead rows and WAL spikes.

#### B: Keep the plain tables but only append

Stop moving the timestamp forward. Add a row only when the counts change. Never update a row.

*Pro*:

1. It removes the hourly updates, which are the largest source of dead rows.

*Con*:

1. Bounding growth still needs a bulk `DELETE` for retention, which produces dead rows,
   grows indexes, and spikes WAL.
2. All history lives in one table that only grows. Vacuum work is never limited to a small part of the data.

#### C: Partition by day and only append

Split both tables into one partition per day, keyed on `LAST_OCCURRENCE`. Only append. 
Add a row when the counts change, and never update a row. Remove old data by dropping whole partitions.
A background task creates each day's partition before it is written.

*Pro*:

1. Retention becomes a partition drop. Dropping a partition frees the space at once.
   It writes no dead rows and needs no vacuum.
2. The hourly updates are gone. Once a day has passed, its partition is read only,
   so autovacuum visits it once and then leaves it alone. Autovacuum work is limited to the current day.
3. PostgreSQL can skip partitions outside the requested range, which speeds up reads over the last
   few days.

*Con*:

1. The data takes more space on disk. Appending stores about one row per subject per day,
   even when nothing changed. The size of a partition grows with the size of the portfolio,
   and total size grows with the portfolio and the retention window together.
2. The timestamp loses one meaning. `LAST_OCCURRENCE` no longer says that a row is still current.
   It now says when the values were first seen.
3. It adds partition maintenance. The application must create partitions ahead of time and drop old ones.

## Decision

We will follow solution **C**. The `DEPENDENCYMETRICS` and `PROJECTMETRICS` tables are partitioned
into one partition per day, keyed on `LAST_OCCURRENCE`. Writes only append. Rows are never updated.
Retention, which version 4 did not have, drops whole partitions. A maintenance task creates each
partition before writers need it.

We accept a larger footprint on disk in exchange for a maintenance cost that stays bounded.
The tradeoff is justifiable because the two costs are not symmetric:

* Storage grows in a straight line, and you absorb it by adding disk, with no downtime.
* Bloat is worse, as once dead rows appear faster than autovacuum can reclaim them, the backlog only grows.
  Bigger tables and indexes slow both queries and vacuum, so vacuum falls further behind.
  Reclaiming that space later requires an expensive, disruptive table or index rewrite.

A predictable, recoverable cost is safer to carry than a self-feeding one.
The real limit in version 4 was this maintenance load, not the amount of data.

A read that needs the value for a given day takes the newest row whose `LAST_OCCURRENCE` is on or before that day.
This works even though an unchanged subject has no row for every day.

## Consequences

Retention is new, and it writes no dead rows. Dropping a partition frees its space in one step,
with no vacuum work and no WAL spike. The tables no longer grow without bound.

The hourly update churn is gone. Past days are read only and are vacuumed once, then stay stable.
Autovacuum work stays limited to the current day's partition, so the metrics tables stop dominating autovacuum.

The tables use more disk than in version 4. Appending stores about one row per component per day,
even when nothing changed. Each row is about 230 bytes, counting both the heap and its indexes.
So for a portfolio of 10 million components, a single daily partition is about 230 * 10000000 = 2.3 GB.
Total storage then depends on three things:

1. the size of the portfolio,
2. how often BOM uploads change the counts,
3. and the length of the retention window.

We accept this as the cost of bounded maintenance.

The meaning of `LAST_OCCURRENCE` changes. It no longer means that a row is still current. It means
when the values were first seen. Any consumer that needs to know whether a value is still current
must get that another way.

This decision is the base that [ADR 029](./029-drop-metrics-fks.md) builds on.
Dropping the metrics foreign keys is only safe because partition drop, not cascading `DELETE`, removes metric rows.

[hyades#1744]: https://github.com/DependencyTrack/hyades/issues/1744
