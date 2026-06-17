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
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.Closeable;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Consumer;
import java.util.function.Supplier;

final class ActivityTaskScheduler implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ActivityTaskScheduler.class);

    private final Jdbi jdbi;
    private final Supplier<Boolean> leadershipSupplier;
    private final MeterRegistry meterRegistry;
    private final long pollIntervalMillis;
    private final IntervalFunction pollBackoffFunction;
    private final Consumer<String> onTasksScheduledCallback;
    private final Thread pollThread;
    private volatile boolean stopped = false;
    private volatile boolean nudged = false;
    private @Nullable Counter pollsCounter;
    private @Nullable MeterProvider<Timer> taskSchedulingLatencyTimer;
    private @Nullable MeterProvider<Counter> tasksScheduledCounter;

    ActivityTaskScheduler(
            Jdbi jdbi,
            Supplier<Boolean> leadershipSupplier,
            MeterRegistry meterRegistry,
            Duration pollIntervalMillis,
            IntervalFunction pollBackoffFunction,
            Consumer<String> onTasksScheduledCallback) {
        this.jdbi = jdbi;
        this.leadershipSupplier = leadershipSupplier;
        this.meterRegistry = meterRegistry;
        this.pollIntervalMillis = pollIntervalMillis.toMillis();
        this.pollBackoffFunction = pollBackoffFunction;
        this.onTasksScheduledCallback = onTasksScheduledCallback;
        this.pollThread = Thread.ofPlatform()
                .name(ActivityTaskScheduler.class.getSimpleName())
                .unstarted(this::pollLoop);
    }

    void start() {
        pollsCounter = Counter
                .builder("dt.dex.engine.activity.task.scheduler.polls")
                .register(meterRegistry);
        taskSchedulingLatencyTimer = Timer
                .builder("dt.dex.engine.activity.task.scheduling.latency")
                .withRegistry(meterRegistry);
        tasksScheduledCounter = Counter
                .builder("dt.dex.engine.activity.tasks.scheduled")
                .withRegistry(meterRegistry);

        pollThread.start();
    }

    void nudge() {
        nudged = true;
        LockSupport.unpark(pollThread);
    }

    @Override
    public void close() {
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
            return PollResult.SKIPPED;
        }

        final List<Queue> queues = jdbi.withHandle(this::getActiveQueuesWithCapacity);
        if (queues.isEmpty()) {
            LOGGER.debug("No updated queues");
            return PollResult.NO_TASKS_SCHEDULED;
        }

        boolean didScheduleTasks = false;
        for (final Queue queue : queues) {
            final Timer.Sample latencySample = Timer.start();
            try (var _ = MDC.putCloseable("queueName", queue.name())) {
                didScheduleTasks |= jdbi.inTransaction(handle -> processQueue(handle, queue));
            } finally {
                latencySample.stop(
                        taskSchedulingLatencyTimer
                                .withTag("queueName", queue.name));
            }
        }

        return didScheduleTasks
                ? PollResult.TASKS_SCHEDULED
                : PollResult.NO_TASKS_SCHEDULED;
    }

    private record Queue(String name, int capacity) {

        private static class RowMapper implements org.jdbi.v3.core.mapper.RowMapper<Queue> {

            @Override
            public Queue map(ResultSet rs, StatementContext ctx) throws SQLException {
                return new Queue(rs.getString("name"), rs.getInt("capacity"));
            }

        }

    }

    private List<Queue> getActiveQueuesWithCapacity(Handle handle) {
        final Query query = handle.createQuery("""
                with cte_candidate as (
                  select name
                       , capacity
                    from dex_activity_task_queue
                   where status = 'ACTIVE'
                )
                select queue.name
                     , queue.capacity
                  from dex_activity_task_queue as queue
                 inner join cte_candidate
                    on cte_candidate.name = queue.name
                 where status = 'ACTIVE'
                   and queue.capacity - (
                         select count(*)
                           from (
                             select 1
                               from dex_activity_task
                              where queue_name = queue.name
                                and status = 'QUEUED'
                              limit cte_candidate.capacity
                           ) as limited
                       ) > 0
                """);

        return query
                .map(new Queue.RowMapper())
                .list();
    }

    private boolean processQueue(Handle handle, Queue queue) {
        final Update update = handle.createUpdate("""
                with
                cte_queue_depth as (
                  select count(*) as depth
                    from (
                      select 1
                        from dex_activity_task
                       where queue_name = :queueName
                         and status = 'QUEUED'
                       limit :capacity
                    ) as limited
                ),
                cte_eligible_task as (
                  select workflow_run_id
                       , created_event_id
                    from dex_activity_task
                   where queue_name = :queueName
                     -- Only consider tasks that are not already queued.
                     and status != 'QUEUED'
                     -- Only consider tasks that are visible.
                     and visible_from <= now()
                   order by priority desc
                          , created_at
                   limit greatest(0, :capacity - (select depth from cte_queue_depth))
                   -- Prevent deadlocks caused by workers concurrently
                   -- polling this table. Note that workflow tasks do not
                   -- have this problem because schedulers and workers poll
                   -- different tables.
                     for no key update
                    skip locked
                )
                update dex_activity_task as wat
                   set status = 'QUEUED'
                     , updated_at = now()
                  from cte_eligible_task
                 where wat.queue_name = :queueName
                   and wat.workflow_run_id = cte_eligible_task.workflow_run_id
                   and wat.created_event_id = cte_eligible_task.created_event_id
                returning activity_name
                """);

        final List<String> scheduledActivityNames = update
                .bind("queueName", queue.name())
                .bind("capacity", queue.capacity())
                .executeAndReturnGeneratedKeys()
                .mapTo(String.class)
                .list();

        final boolean didSchedule = !scheduledActivityNames.isEmpty();
        handle.afterCommit(() -> {
            for (final String activityName : scheduledActivityNames) {
                tasksScheduledCounter
                        .withTag("activityName", activityName)
                        .increment();
            }

            if (didSchedule) {
                onTasksScheduledCallback.accept(queue.name());
            }
        });

        return didSchedule;
    }

}
