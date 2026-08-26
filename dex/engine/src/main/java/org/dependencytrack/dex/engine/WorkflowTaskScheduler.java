/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.dex.engine;

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.StatementContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.Closeable;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.dependencytrack.dex.engine.MdcKeys.MDC_QUEUE_NAME;

final class WorkflowTaskScheduler implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowTaskScheduler.class);
    private static final int CONCURRENCY_KEY_HINT_BUDGET_FACTOR = 4;

    private final Jdbi jdbi;
    private final Supplier<Boolean> leadershipSupplier;
    private final long pollIntervalMillis;
    private final IntervalFunction pollBackoffFunction;
    private final Consumer<String> onTasksScheduled;
    private final ConcurrencyKeyMaintenanceWorker concurrencyKeyMaintenanceWorker;
    private final Thread pollThread;
    private final Counter pollsCounter;
    private final MeterProvider<Timer> taskSchedulingLatencyTimer;
    private final MeterProvider<Counter> tasksScheduledCounter;
    private volatile boolean stopped = false;
    private volatile boolean nudged = false;
    private boolean wasLeader = false;

    WorkflowTaskScheduler(
            Jdbi jdbi,
            Supplier<Boolean> leadershipSupplier,
            MeterRegistry meterRegistry,
            Duration pollInterval,
            IntervalFunction pollBackoffFunction,
            Duration concurrencyKeyWakeupRepairInterval,
            Consumer<String> onTasksScheduled) {
        this.jdbi = jdbi;
        this.leadershipSupplier = leadershipSupplier;
        this.pollIntervalMillis = pollInterval.toMillis();
        this.pollBackoffFunction = pollBackoffFunction;
        this.onTasksScheduled = onTasksScheduled;
        this.concurrencyKeyMaintenanceWorker =
                new ConcurrencyKeyMaintenanceWorker(
                        jdbi,
                        leadershipSupplier,
                        meterRegistry,
                        concurrencyKeyWakeupRepairInterval,
                        this::nudge);
        this.pollThread = Thread.ofPlatform()
                .name(getClass().getSimpleName())
                .unstarted(this::pollLoop);
        this.pollsCounter = Counter
                .builder("dt.dex.engine.workflow.task.scheduler.polls")
                .register(meterRegistry);
        this.taskSchedulingLatencyTimer = Timer
                .builder("dt.dex.engine.workflow.task.scheduling.latency")
                .withRegistry(meterRegistry);
        this.tasksScheduledCounter = Counter
                .builder("dt.dex.engine.workflow.tasks.scheduled")
                .withRegistry(meterRegistry);
    }

    void start() {
        concurrencyKeyMaintenanceWorker.start();
        pollThread.start();
    }

    void nudge() {
        nudged = true;
        LockSupport.unpark(pollThread);
    }

    @Override
    public void close() {
        concurrencyKeyMaintenanceWorker.close();

        if (pollThread.isAlive()) {
            LOGGER.debug("Waiting for poll thread to stop");
            stopped = true;
            LockSupport.unpark(pollThread);

            try {
                final boolean terminated = pollThread.join(Duration.ofSeconds(3));
                if (!terminated) {
                    LOGGER.warn("Poll thread did not terminate in time; Interrupting it");
                    pollThread.interrupt();
                }
            } catch (InterruptedException e) {
                LOGGER.warn("Interrupted waiting for poll thread to stop", e);
                Thread.currentThread().interrupt();
                pollThread.interrupt();
            }
        }
    }

    private void pollLoop() {
        long nowMillis;
        long lastPolledAtMillis = 0;
        long nextPollAtMillis;
        long nextPollDueInMillis;
        int pollsWithoutSchedules = 0;
        int consecutiveErrors = 0;

        while (!stopped && !Thread.currentThread().isInterrupted()) {
            if (nudged) {
                nudged = false;
                pollsWithoutSchedules = 0;
            }

            if (pollsWithoutSchedules < 3 && consecutiveErrors == 0) {
                nowMillis = System.currentTimeMillis();
                nextPollAtMillis = lastPolledAtMillis + pollIntervalMillis;
                nextPollDueInMillis = nextPollAtMillis > nowMillis
                        ? nextPollAtMillis - nowMillis
                        : 0;
            } else {
                final int backoffAttempts = Math.max(pollsWithoutSchedules - 2, consecutiveErrors);
                nextPollDueInMillis = Math.max(
                        pollBackoffFunction.apply(backoffAttempts),
                        pollIntervalMillis);
                LOGGER.debug(
                        "Backing off for {}ms (attempt={}, pollsWithoutSchedules={}, consecutiveErrors={})",
                        nextPollDueInMillis,
                        backoffAttempts,
                        pollsWithoutSchedules,
                        consecutiveErrors);
            }

            if (nextPollDueInMillis > 0) {
                LOGGER.debug("Waiting for next poll to be due in {}ms", nextPollDueInMillis);
                LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(nextPollDueInMillis));
                if (Thread.currentThread().isInterrupted() || stopped) {
                    break;
                }

                // Enforce minimum poll interval even when nudged.
                final long elapsedSinceLastPoll = System.currentTimeMillis() - lastPolledAtMillis;
                if (elapsedSinceLastPoll < pollIntervalMillis) {
                    continue;
                }
            }

            lastPolledAtMillis = System.currentTimeMillis();
            pollsCounter.increment();

            try {
                final PollResult pollResult = poll();
                if (pollResult == PollResult.TASKS_SCHEDULED) {
                    pollsWithoutSchedules = 0;
                } else {
                    pollsWithoutSchedules++;
                }
                consecutiveErrors = 0;
            } catch (RuntimeException e) {
                consecutiveErrors++;
                LOGGER.error("Unexpected error occurred while scheduling activity tasks", e);
            }
        }
    }

    private enum PollResult {
        TASKS_SCHEDULED,
        NO_TASKS_SCHEDULED,
        SKIPPED
    }

    private PollResult poll() {
        if (!leadershipSupplier.get()) {
            LOGGER.debug("Not the leader; Skipping poll");
            wasLeader = false;
            return PollResult.SKIPPED;
        }

        if (!wasLeader) {
            wasLeader = true;
            concurrencyKeyMaintenanceWorker.nudge();
        }

        final List<Queue> queues = jdbi.withHandle(this::getActiveQueuesWithCapacity);
        if (queues.isEmpty()) {
            LOGGER.debug("No active queues with capacity");
            return PollResult.NO_TASKS_SCHEDULED;
        }

        boolean madeProgress = false;
        for (final Queue queue : queues) {
            final Timer.Sample latencySample = Timer.start();
            try (var _ = MDC.putCloseable(MDC_QUEUE_NAME, queue.name())) {
                madeProgress |= jdbi.inTransaction(handle -> processQueue(handle, queue));
            } finally {
                latencySample.stop(
                        taskSchedulingLatencyTimer
                                .withTag("queueName", queue.name()));
            }
        }

        return madeProgress
                ? PollResult.TASKS_SCHEDULED
                : PollResult.NO_TASKS_SCHEDULED;
    }

    private record Queue(String name, int remainingCapacity) {

        private static class RowMapper implements org.jdbi.v3.core.mapper.RowMapper<Queue> {

            @Override
            public Queue map(ResultSet rs, StatementContext ctx) throws SQLException {
                return new Queue(rs.getString("name"), rs.getInt("remaining_capacity"));
            }

        }

    }

    private List<Queue> getActiveQueuesWithCapacity(Handle handle) {
        final Query query = handle.createQuery("""
                select name
                     , remaining_capacity
                  from (
                    select name
                         , capacity - (
                             select count(*)
                               from (
                                 select 1
                                   from dex_workflow_task as task
                                  where task.queue_name = queue.name
                                  limit queue.capacity
                               ) as limited
                           ) as remaining_capacity
                      from dex_workflow_task_queue as queue
                     where status = 'ACTIVE'
                  ) as queue_with_capacity
                 where remaining_capacity > 0
                """);

        return query
                .map(new Queue.RowMapper())
                .list();
    }

    private record SchedulingResult(
            List<String> workflowNames,
            int consumedConcurrencyKeyHints) {
    }

    private boolean processQueue(Handle handle, Queue queue) {
        final SchedulingResult result = scheduleEligibleRuns(handle, queue);

        final List<String> scheduledWorkflowNames = result.workflowNames();
        final boolean didSchedule = !scheduledWorkflowNames.isEmpty();
        handle.afterCommit(() -> {
            for (final String workflowName : scheduledWorkflowNames) {
                tasksScheduledCounter
                        .withTag("workflowName", workflowName)
                        .increment();
            }

            if (didSchedule) {
                onTasksScheduled.accept(queue.name());
            }
        });

        // Consumed hints count as progress even when nothing was admitted.
        // Draining a flood of stale hints must not be slowed by poll backoff.
        return didSchedule || result.consumedConcurrencyKeyHints() > 0;
    }

    private SchedulingResult scheduleEligibleRuns(Handle handle, Queue queue) {
        // Disable JIT for this transaction. The scheduling query uses
        // multiple correlated subqueries which throw off Postgres'
        // row estimates, leading it to enable JIT. Unfortunately, JIT adds
        // more overhead than the query usually ends up running for.
        //
        // Force custom query plans for this transaction. The JDBC driver uses
        // server-side prepared statements. Generic plans cached while the
        // tables are (close to) empty degrade polls by orders of magnitude
        // during bursts.
        handle.execute("""
                select set_config('jit', 'off', /* is_local */ true)
                     , set_config('plan_cache_mode', 'force_custom_plan', /* is_local */ true)
                """);

        final Query query = handle.createQuery("""
                with
                -- A bounded batch of wakeups. Within each priority, freed concurrency keys
                -- come first so keys freed mid-burst are not buried behind a flood of creation wakeups.
                -- The rest follow in arrival order, so no key is starved by newer arrivals.
                cte_hint as (
                  select concurrency_key
                       , version
                    from dex_workflow_concurrency_key_wakeup
                   where queue_name = :queueName
                   order by priority desc
                          , freed desc
                          , created_at
                   limit :concurrencyKeyHintBudget
                ),
                -- Verify each hinted key against the run, task, and inbox tables before admission.
                -- Note that hints carry no authority. A stale hint at worst costs a wasted probe,
                -- but never a wrong admission. The result has one row per hint, so the consuming
                -- delete stays a one-to-one join.
                -- NB: All probes are laterals with limit 1,
                -- immune to join commutation and bounded by the hint budget.
                cte_verified_hint as (
                  select cte_hint.concurrency_key
                       , cte_hint.version
                       , run.id
                       , run.workflow_name
                       , run.priority
                       , run.sticky_to
                       , run.sticky_until
                       , (
                           run.id is not null
                           and has_executing is null
                           and has_queued_task is null
                           and has_message is not null
                         ) as schedulable
                       -- Only consume hints for reasons that don't depend on the clock.
                       -- `has_message` must NOT be one of them: `now()` is this transaction's
                       -- start time, but this statement sees rows committed after it, since we use
                       -- READ_COMMITTED isolation. Such a run is visible here, yet its message looks
                       -- not-yet-due (i.e. `visible_from > now()`), and deleting its just-written
                       -- hint would stall it until the next repair.
                       , (
                           run.id is null
                           or has_executing is not null
                           or has_queued_task is not null
                         ) as consumable
                    from cte_hint
                    -- The key's highest priority CREATED run.
                    left join lateral (
                     select candidate.id
                       from dex_workflow_run as candidate
                      where candidate.concurrency_key = cte_hint.concurrency_key
                        and candidate.status = 'CREATED'
                      order by candidate.priority desc
                             , candidate.id
                      limit 1
                    ) as winner on true
                    left join dex_workflow_run as run
                      on run.id = winner.id
                     and run.task_queue_name = :queueName
                    left join lateral (
                     select 1
                       from dex_workflow_run as executing
                      where executing.concurrency_key = cte_hint.concurrency_key
                        and executing.concurrency_key is not null
                        and executing.status in ('RUNNING', 'SUSPENDED')
                      limit 1
                    ) as has_executing on true
                    left join lateral (
                     select 1
                       from dex_workflow_task as task
                      where task.queue_name = :queueName
                        and task.concurrency_key = cte_hint.concurrency_key
                      limit 1
                    ) as has_queued_task on true
                    left join lateral (
                     select 1
                       from dex_workflow_inbox as inbox
                      where inbox.workflow_run_id = run.id
                        and inbox.visible_from <= now()
                      limit 1
                    ) as has_message on true
                ),
                cte_locked_hint as (
                  select wakeup.concurrency_key
                       , wakeup.version
                    from dex_workflow_concurrency_key_wakeup as wakeup
                   inner join cte_verified_hint as verified
                      on verified.concurrency_key = wakeup.concurrency_key
                   where wakeup.queue_name = :queueName
                     and wakeup.version = verified.version
                     and verified.consumable
                   order by wakeup.concurrency_key
                     for update of wakeup
                ),
                cte_consumed_hint as (
                  delete
                    from dex_workflow_concurrency_key_wakeup as wakeup
                   using cte_locked_hint as locked
                   where wakeup.queue_name = :queueName
                     and wakeup.concurrency_key = locked.concurrency_key
                     and wakeup.version = locked.version
                  returning 1
                ),
                cte_eligible_run as (
                  -- CREATED runs without concurrency key.
                  (
                    select run.id
                         , run.workflow_name
                         , run.priority
                         , run.sticky_to
                         , run.sticky_until
                         , run.concurrency_key
                      from (
                        -- NB: Selecting only id and priority keeps this an index-only scan.
                        select candidate.id
                             , candidate.priority
                          from dex_workflow_run as candidate
                         -- NB: Lateral joins with limit 1 prevent the planner from switching
                         -- to a semi-join, which always performs worse here. DO NOT change
                         -- these to exists(...) without prior benchmarking!
                         cross join lateral (
                           select 1
                             from dex_workflow_inbox as inbox
                            where inbox.workflow_run_id = candidate.id
                              and inbox.visible_from <= now()
                            limit 1
                         ) as has_message
                          left join lateral (
                           select 1
                             from dex_workflow_task as task
                            where task.queue_name = :queueName
                              and task.workflow_run_id = candidate.id
                            limit 1
                          ) as has_task on true
                         where candidate.task_queue_name = :queueName
                           and candidate.status = 'CREATED'
                           and candidate.concurrency_key is null
                           and has_task is null
                         order by candidate.priority desc
                                , candidate.id
                         limit :limit
                      ) as top
                     inner join dex_workflow_run as run
                        on run.id = top.id
                     order by top.priority desc
                            , top.id
                     limit :limit
                  )
                  union all
                  -- RUNNING / SUSPENDED runs.
                  (
                    select run.id
                         , run.workflow_name
                         , run.priority
                         , run.sticky_to
                         , run.sticky_until
                         , run.concurrency_key
                      from (
                        select candidate.id
                             , candidate.priority
                          from dex_workflow_run as candidate
                         cross join lateral (
                           select 1
                             from dex_workflow_inbox as inbox
                            where inbox.workflow_run_id = candidate.id
                              and inbox.visible_from <= now()
                            limit 1
                         ) as has_message
                          left join lateral (
                           select 1
                             from dex_workflow_task as task
                            where task.queue_name = :queueName
                              and task.workflow_run_id = candidate.id
                            limit 1
                          ) as has_task on true
                         where candidate.task_queue_name = :queueName
                           and candidate.status in ('RUNNING', 'SUSPENDED')
                           and has_task is null
                         order by candidate.priority desc
                                , candidate.id
                         limit :limit
                      ) as top
                     inner join dex_workflow_run as run
                        on run.id = top.id
                     order by top.priority desc
                            , top.id
                     limit :limit
                  )
                  union all
                  -- Schedulable CREATED runs with concurrency key.
                  (
                    select id
                         , workflow_name
                         , priority
                         , sticky_to
                         , sticky_until
                         , concurrency_key
                      from cte_verified_hint
                     where schedulable
                     order by priority desc
                            , id
                     limit :limit
                  )
                  order by priority desc
                         , id
                  limit :limit
                ),
                cte_scheduled_task as (
                  insert into dex_workflow_task (
                    queue_name
                  , workflow_run_id
                  , workflow_name
                  , priority
                  , sticky_to
                  , sticky_until
                  , concurrency_key
                  )
                  select :queueName
                       , id
                       , workflow_name
                       , priority
                       , sticky_to
                       , sticky_until
                       , concurrency_key
                    from cte_eligible_run
                  on conflict (queue_name, workflow_run_id) do nothing
                  returning workflow_name
                )
                select scheduled.workflow_name
                     , consumed.consumed_hint_count
                  from (
                    select count(*) as consumed_hint_count
                      from cte_consumed_hint
                  ) as consumed
                  left join cte_scheduled_task as scheduled
                    on true
                """);

        final var consumedConcurrencyKeyHints = new long[]{0};
        final List<String> workflowNames = query
                .bind("queueName", queue.name())
                .bind("limit", queue.remainingCapacity())
                .bind("concurrencyKeyHintBudget", queue.remainingCapacity() * CONCURRENCY_KEY_HINT_BUDGET_FACTOR)
                .map((rs, _) -> {
                    consumedConcurrencyKeyHints[0] = rs.getLong("consumed_hint_count");
                    return rs.getString("workflow_name");
                })
                // NB: workflow_name is null when hints were consumed but nothing was scheduled.
                .filter(Objects::nonNull)
                .collectIntoList();

        return new SchedulingResult(workflowNames, Math.toIntExact(consumedConcurrencyKeyHints[0]));
    }

}
