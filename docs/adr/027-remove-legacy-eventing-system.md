| Status   | Date       | Author(s)                            |
|:---------|:-----------|:-------------------------------------|
| Accepted | 2026-05-22 | [@nscuro](https://github.com/nscuro) |

## Context

The old in-memory event system we inherited from Alpine was used as a task
runner, not as a real publish-subscribe bus. All events had only one
listener, and that listener was the task the event was meant to start. To
stop two nodes from running the same scheduled task at the same time, we
used [ShedLock] on top. ShedLock needs its own database table and a pair of
minimum and maximum lock time settings per task. With many tasks, this added
up to a lot of settings that operators had to manage, and these settings did
not really add much on top of what the schedule itself already says.

A durable execution engine ([dex](../../dex)) has been available for some time.
It runs durable, observable, multi-step work and gives us safe re-runs,
persistence, and retries. It has no concept of cron-based recurring scheduling,
and we do not want to add one. What we need is a separate scheduler that fires
jobs on a schedule and works correctly in clustered deployments. So the two are
complementary, not competing. Many of the jobs we schedule do little more than
start a dex workflow and exit. [ADR-002] looked at [db-scheduler] for workflow
orchestration and did not choose it. The reason was that db-scheduler runs
multi-step work as a chain of jobs and cannot fork and join them. That reason
applies only to workflows, not to plain recurring scheduling.

Alpine is being removed step by step, and its code is being moved into the
apiserver and other modules. Code that lives only in Alpine and has a good
replacement is old code we want to remove.

We want to remove this kind of old code before the v5 GA release. After GA,
settings and database tables become promises we have to keep, so changes
like this one get much harder. Doing it now means one less system to
maintain, document, and support later.

## Decision

We will remove the old event system. Each scheduled task becomes a plain
runnable.

We will use [db-scheduler] to run recurring tasks. It runs each job once per
cluster on a cron schedule and coordinates across nodes on its own,
so ShedLock is no longer needed. The minimum and maximum lock time settings
on each task are removed as well. We schedule only a few tasks, and each one
runs about one or two times a day, so the volume is very low.
We choose db-scheduler for its correctness, not for its scalability.
The library is small, well-maintained, and introduces no additional transitive dependencies.

We considered a scheduler of our own, built on a [compare-and-swap] update of
each task's next fire time. We rejected it. It would do by hand what
db-scheduler already gives us.

db-scheduler owns its own database table, which we will manage through Flyway.

We move the internal component identification job to the durable execution
engine. It scans the whole portfolio, its runtime grows with the size of the
portfolio, and only one run may be active at a time. Workflow instance IDs
give us this singleton behavior, as described in [ADR-002].

We will no longer run internal component identification on a schedule.
The internal flag is already set on every component when its BOM is uploaded,
and the rules behind the flag change very rarely. When an operator changes
the rules, we expect them to start the workflow by hand via UI.

## Consequences

The codebase loses a large amount of old code and one of its two ways to
coordinate tasks across nodes.

Operators have far fewer settings to manage. The minimum and maximum lock
time settings on each task are gone, and so are the worker thread pool
settings that the old event system needed.

Crash recovery gets better, because db-scheduler finds a dead node through
regular heartbeats instead of waiting out a long claim window sized to the
job's longest run.

Operators must now start internal component identification by hand after
changing the rules for what counts as internal. The six-hour scan no longer
runs on its own. The button to start it is in the UI, directly next to the
regular expression input fields. Expecting the button to be pressed is
reasonable.

It is now clearer where scheduled work belongs:

* Simple repeating jobs use db-scheduler
* Long, multi-step, or coordinated work uses the durable execution engine.

Because this lands before GA, we break no compatibility promise.

[ADR-002]: ./002-workflow-orchestration.md
[ShedLock]: https://github.com/lukas-krecan/ShedLock
[compare-and-swap]: https://en.wikipedia.org/wiki/Compare-and-swap
[db-scheduler]: https://github.com/kagkarlsson/db-scheduler
