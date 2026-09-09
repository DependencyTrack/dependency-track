| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-08-20 | [@nscuro](https://github.com/nscuro) |

## Context

The scheduled portfolio analysis creates one `analyze-project` workflow run per project,
by iterating over all active projects in the portfolio, and creating runs in batches of up to 1000.
For large portfolios, this can lead to tens of thousands of runs to be scheduled in under a minute.

BOM uploads and manual API calls trigger the same workflow, so an analysis is either
client-triggered or scheduled. All runs are serialized by the concurrency key
`analyze-project:<project-uuid>`, so at most one analysis per project runs at a time.
That is necessary to avoid data races, particularly during reconciliation of vuln
analyzer results ([ADR 013]).

Users [report][gh-discussion-7034] that while the scheduled analysis runs,
an upload-triggered analysis occasionally takes tens of minutes to *start*,
for work that then completes in under a minute.

This happens despite runs triggered by uploads having a higher priority (50) than those triggered
on schedule (0), because priority only controls admission, but doesn't preempt.
If two runs share a concurrency key, and the run with priority 0 is already executing when
the run with priority 50 gets created, the latter is blocked until the former completes.

Nothing holds the scheduled runs back either. The capacity of the workflow task queue counts
queued tasks, and a run that waits for an activity has none. So almost every scheduled run
starts within minutes of its creation, and holds the key of its project until it completes.

It has also been [noted][gh-issue-6642] that the bursty scheduling of `analyze-project`
workflow runs can cause undesired load spikes in a specific time of day.

### Possible Solutions

#### A: Raise the capacity of the activity task queues

Increase the throughput of activity tasks in the cluster by raising task queue capacities.

*Pro*:

1. Configuration only.

*Con*:

1. The capacity caps concurrent execution across the cluster to protect shared resources (i.e. the DB).
2. Doesn't help for runs blocked on retries.

#### B: Raise the priority of the run that holds the key

When a run with concurrency key gets created, look for other runs with the same key,
and bump their priority to make them complete sooner.

Challenge: the priority of a run is inherited (and denormalized into) all child runs
and activities it spawns. Bumping the priority of a run thus involves updating records
across multiple tables.

*Pro*:

1. Resolves the problem using only existing scheduling semantics.

*Con*:

1. Priority is part of a run's event history, so changing it mid-flight breaks determinism.
2. More table bloat and increased risk of deadlocks because the tables that need updating are hot.
3. When many uploads occur while many scheduled analyses are already running, we still end up with
   many runs of equally highly-bumped priorities. Effectiveness declines the larger and more active
   an instance is.

#### C: Cancel the run that holds the key

Similar to [GitHub Actions' `cancel-in-progress`][gh-job-concurrency]: Cancel the existing run
when another run with identical concurrency key gets created.

*Pro*:

1. Gives the user the fastest result.

*Con*:

1. Discards analyzer calls already made, and leaves partial state to clean up.
2. Run cancellation is eventually consistent, so we can't guarantee timeliness.

#### D: Spread the schedule over the day

Instead of scheduling all analyses at once, spread them out over the day.

*Pro*:

1. No new state to keep.

*Con*:

1. The total analysis work per day is fixed, so the chance of a collision is unchanged.

#### E: Let dex limit concurrent runs

dex can't currently limit how many runs of a given workflow can execute at a time.

*Pro*:

1. The limit would be available to every workflow.

*Con*:

1. Scheduled and client-triggered analyses would share one admission order,
   where a steady stream of uploads can keep the schedule waiting forever.
2. Counting runs against the capacity of the task queue would consume the capacity that lets
   already-executing runs continue, so at the limit no run could finish. The limit needs its own accounting.

#### F: Limit how many scheduled analyses run at once

Instead of blindly creating new runs on schedule, enforce a limit as to how many
scheduled runs can be in non-terminal state. Create only as many runs as the remaining
capacity allows for.

*Pro*:

1. Addresses the root cause (too many runs being scheduled in short succession).
2. Needs no change to how the engine orders or schedules work.
3. Adapts to actual analysis durations instead of predicting them.

*Con*:

1. Needs a way to count analyses in flight, and somewhere to remember what is still due.

## Decision

We will limit how many scheduled analyses run at once, i.e. [option F].

The API server keeps one row per active project in a `PROJECT_LAST_ANALYSIS` table,
recording when an analysis for it was last attempted:

| Column         | Type          | Notes                                           |
|:---------------|:--------------|:------------------------------------------------|
| `PROJECT_ID`   | `BIGINT`      | PK, FK -> `PROJECT`                             |
| `ATTEMPTED_AT` | `TIMESTAMPTZ` | Never `NULL`, `'epoch'` until the first attempt |

A recurring task offers the projects whose analysis is oldest and older than the maximum age,
as many as the in-flight limit leaves room for, and records the attempt.
The maximum analysis age replaces the cron expression of the task.

* The *attempt* is recorded, not the outcome. A record of successes only would make a project whose
  analysis always fails come up again on every tick.
* Only projects whose runs the engine actually created are recorded, so a project it skipped keeps
  its old timestamp and is offered again.
* Client-triggered analyses are recorded too. They do the same work, so a project with a recent
  one does not need the schedule to repeat it.
* Only the schedule's own analyses count towards the limit. A client-triggered analysis never
  checks the limit, so counting those would let a busy deployment starve the schedule.
* Triggers keep the table in sync with the `PROJECT` table, and only active projects have a row,
  since inactive projects are never analyzed.
* On upgrade, projects that already exist start at the time of their last successful analysis,
  taken from the `PROJECT` table. Seeding them all at `'epoch'` would make the entire portfolio
  due at once.

## Consequences

* The wait for a user-triggered analysis is bounded by the limit and the queue capacity,
  rather than by the size of the portfolio. Fewer keys are held at once, so collisions become rarer *and* shorter.
* No project can be starved, regardless of the load. The guarantee changes from "every project on every run
  of the schedule", which the previous design could not keep, to "every project due".
* The database gets one more table and two more triggers on the `PROJECT` table.
* The `PROJECT` table's existing last-analyzed column records successful completions and is unchanged.
  It seeds the new table once, on upgrade. From then on only the new one, which records attempts,
  decides what to analyze next.
* The cron expression of the portfolio analysis task is removed, and startup fails while it is still set.
  Analysis load moves from one nightly burst to a steady trickle, so operators who used it to keep
  analyses out of business hours lose that.

[ADR 013]: ./013-finding-status.md
[gh-discussion-7034]: https://github.com/DependencyTrack/dependency-track/discussions/7034
[gh-issue-6642]: https://github.com/DependencyTrack/dependency-track/issues/6642
[gh-job-concurrency]: https://docs.github.com/en/enterprise-cloud@latest/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idconcurrency
[option F]: #f-limit-how-many-scheduled-analyses-run-at-once
