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

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.Closeable;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

final class ConcurrencyKeyMaintenanceWorker implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConcurrencyKeyMaintenanceWorker.class);
    private static final int PRIMING_REPAIR_BUDGET = 100_000;
    private static final int LARGE_BACKLOG_THRESHOLD = 100_000;
    private static final String TRUNCATION_MARKER = "";

    private final Jdbi jdbi;
    private final Supplier<Boolean> leadershipSupplier;
    private final long repairIntervalMillis;
    private final Runnable onWakeupsRepaired;
    private final Counter repairedWakeupsCounter;
    private @Nullable ScheduledExecutorService executor;
    private volatile boolean stopped = false;
    private boolean wasLeader = false;

    ConcurrencyKeyMaintenanceWorker(
            Jdbi jdbi,
            Supplier<Boolean> leadershipSupplier,
            MeterRegistry meterRegistry,
            Duration repairInterval,
            Runnable onWakeupsRepaired) {
        this.jdbi = jdbi;
        this.leadershipSupplier = leadershipSupplier;
        this.repairIntervalMillis = repairInterval.toMillis();
        this.onWakeupsRepaired = onWakeupsRepaired;
        this.repairedWakeupsCounter = Counter.builder("dt.dex.engine.workflow.concurrency.key.wakeups.repaired")
                .register(meterRegistry);
    }

    void start() {
        executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform().name(getClass().getSimpleName()).factory());
        executor.scheduleAtFixedRate(
                this::maybeRepair, /* initialDelay */ 0, repairIntervalMillis, TimeUnit.MILLISECONDS);
    }

    void nudge() {
        if (executor != null) {
            executor.execute(this::maybeRepair);
        }
    }

    @Override
    public void close() {
        stopped = true;
        if (executor != null) {
            executor.shutdownNow();
            try {
                if (!executor.awaitTermination(3, TimeUnit.SECONDS)) {
                    LOGGER.warn("Wakeup repair did not terminate in time");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void maybeRepair() {
        if (stopped) {
            return;
        }

        if (!leadershipSupplier.get()) {
            wasLeader = false;
            return;
        }

        final boolean leadershipAcquired = !wasLeader;
        wasLeader = true;

        try {
            repair(leadershipAcquired);
        } catch (RuntimeException e) {
            LOGGER.error("Failed to repair concurrency key wakeups", e);
        }
    }

    private void repair(boolean leadershipAcquired) {
        // The wakeup table is unlogged so it can be truncated by database
        // crash or standby promotion. Detect this by absense of our truncation
        // marker sentinel row.
        final boolean tableWasTruncated = jdbi.withHandle(handle -> handle.createQuery("""
                        select not exists(
                          select 1
                            from dex_workflow_concurrency_key_wakeup
                           where queue_name = :truncationMarker
                             and concurrency_key = :truncationMarker
                        )
                        """)
                .bind("truncationMarker", TRUNCATION_MARKER)
                .mapTo(boolean.class)
                .one());

        // We treat leadership change the same as a truncated wakeup table.
        // A new leader node starts with zero knowledge about the backlog.
        final boolean crashRecovery = leadershipAcquired || tableWasTruncated;

        final List<String> queueNames = jdbi.withHandle(
                handle -> handle.createQuery("""
                        select name
                          from dex_workflow_task_queue
                         where status = 'ACTIVE'
                        """).mapTo(String.class).list());

        boolean repaired = false;
        for (final String queueName : queueNames) {
            if (stopped) {
                return;
            }

            try (var _ = MDC.putCloseable("queueName", queueName)) {
                repaired |= jdbi.inTransaction(handle -> repairQueue(handle, queueName, crashRecovery));
            }
        }

        jdbi.useTransaction(handle -> handle.createUpdate("""
                        insert into dex_workflow_concurrency_key_wakeup (queue_name, concurrency_key)
                        values (:truncationMarker, :truncationMarker)
                        on conflict (queue_name, concurrency_key) do nothing
                        """)
                .bind("truncationMarker", TRUNCATION_MARKER)
                .execute());
        if (repaired) {
            onWakeupsRepaired.run();
        }
    }

    private boolean repairQueue(Handle handle, String queueName, boolean crashRecovery) {
        // Disable JIT for this transaction. The repair queries use multiple
        // correlated subqueries which throw off Postgres' row estimates,
        // leading it to enable JIT. Unfortunately, JIT adds more overhead
        // than the queries usually end up running for.
        //
        // Force custom query plans for this transaction. The JDBC driver uses
        // server-side prepared statements. Generic plans cached while the
        // tables are (close to) empty produce degenerate plans during bursts.
        handle.execute("""
                select set_config('jit', 'off', /* is_local */ true)
                     , set_config('plan_cache_mode', 'force_custom_plan', /* is_local */ true)
                """);

        // Overwrite the global query timeout (10s by default) to 5min.
        // The repair queries can genuinely run longer, especially on crash recovery.
        final int queryTimeoutSeconds = Math.toIntExact(TimeUnit.MINUTES.toSeconds(5));

        final int keyedRunBacklog = handle.createQuery("""
                        select count(*)
                          from (
                            select 1
                              from dex_workflow_run
                             where concurrency_key is not null
                               and status = 'CREATED'
                             limit :probeLimit
                          ) as probe
                        """)
                .bind("probeLimit", LARGE_BACKLOG_THRESHOLD + 1)
                .setQueryTimeout(queryTimeoutSeconds)
                .mapTo(Integer.class)
                .one();

        final Query repairQuery = handle.createQuery("""
                        with
                        <#if largeKeyedRunBacklog>
                        -- Identify the highest priority CREATED run per concurrency key.
                        cte_next_concurrency_key_run as (
                          select distinct on (concurrency_key) concurrency_key
                               , id
                            from dex_workflow_run
                           where concurrency_key is not null
                             and status = 'CREATED'
                           order by concurrency_key
                                  , priority desc
                                  , id
                        ),
                        -- Next runs whose concurrency key has no executing run and no queued task.
                        -- NB: The `not exists(...)` checks execute as bulk anti joins,
                        -- which require roughly correct row estimates.
                        -- A large backlog makes this more likely to be the case, since the tables
                        -- can't grow this far without autoanalyze refreshing statistics.
                        cte_schedulable_concurrency_key_run_id as (
                          select next_run.id
                            from cte_next_concurrency_key_run as next_run
                           where not exists(
                             select 1
                               from dex_workflow_run as executing
                              where executing.concurrency_key = next_run.concurrency_key
                                and executing.status in ('RUNNING', 'SUSPENDED')
                           )
                             and not exists(
                               select 1
                                 from dex_workflow_task as task
                                where task.queue_name = :queueName
                                  and task.concurrency_key = next_run.concurrency_key
                             )
                        ),
                        <#else>
                        -- Identify the highest priority CREATED run per concurrency key,
                        -- unless the key is blocked by an executing run or queued task.
                        -- NB: No joins or `exists()` are used, because they can degrade
                        -- into per-row rescans when statistics are stale, which is the
                        -- case when a burst starts on a previously idle system.
                        cte_schedulable_concurrency_key_run_id as (
                          select id
                            from (
                              select distinct on (concurrency_key) concurrency_key
                                   , id
                                from (
                                  select concurrency_key
                                       , id
                                       , priority
                                       , 0 as blocked
                                    from dex_workflow_run
                                   where concurrency_key is not null
                                     and status = 'CREATED'
                                  union all
                                  select concurrency_key
                                       , null
                                       , null
                                       , 1
                                    from dex_workflow_run
                                   where concurrency_key is not null
                                     and status in ('RUNNING', 'SUSPENDED')
                                  union all
                                  select concurrency_key
                                       , null
                                       , null
                                       , 1
                                    from dex_workflow_task
                                   where queue_name = :queueName
                                     and concurrency_key is not null
                                ) as contender
                               order by concurrency_key
                                      , blocked desc
                                      , priority desc
                                      , id
                            ) as next_concurrency_key_run
                           where id is not null
                        ),
                        </#if>
                        cte_repaired_hint as (
                          insert into dex_workflow_concurrency_key_wakeup (
                            queue_name
                          , concurrency_key
                          , priority
                          , freed
                          )
                          select :queueName
                               , missing.concurrency_key
                               , missing.priority
                               , true
                            from (
                              select run.concurrency_key
                                   , run.priority
                                from cte_schedulable_concurrency_key_run_id as schedulable
                               inner join dex_workflow_run as run
                                  on run.id = schedulable.id
                               where run.task_queue_name = :queueName
                                 and exists(
                                   select 1
                                     from dex_workflow_inbox as inbox
                                    where inbox.workflow_run_id = run.id
                                      and inbox.visible_from <= now()
                                 )
                                 and not exists(
                                   select 1
                                     from dex_workflow_concurrency_key_wakeup as wakeup
                                    where wakeup.queue_name = :queueName
                                      and wakeup.concurrency_key = run.concurrency_key
                                 )
                            <#if crashRecovery>
                               -- During crash recovery, repair the highest priority keys first
                               -- in a bounded batch. If the backlog is large, this gives the
                               -- scheduler a head-start to work on the most important work,
                               -- instead of waiting for a potentially multi-minute full restore.
                               order by run.priority desc
                                      , run.concurrency_key
                               limit :primingRepairBudget
                            </#if>
                            ) as missing
                           order by missing.concurrency_key
                          on conflict (queue_name, concurrency_key) do nothing
                          returning 1
                        )
                        select count(*) as repaired_count
                          from cte_repaired_hint
                        """)
                .setQueryTimeout(queryTimeoutSeconds)
                .define("largeKeyedRunBacklog", keyedRunBacklog > LARGE_BACKLOG_THRESHOLD)
                .define("crashRecovery", crashRecovery)
                .bind("queueName", queueName);
        if (crashRecovery) {
            repairQuery.bind("primingRepairBudget", PRIMING_REPAIR_BUDGET);
        }

        return repairQuery
                        .map((rs, _) -> {
                            final long repairedCount = rs.getLong("repaired_count");
                            if (repairedCount > 0 && !crashRecovery) {
                                // Outside of crash recovery, every repair means a write path failed
                                // to leave a hint, which is a defect we should know about.
                                repairedWakeupsCounter.increment(repairedCount);
                                LOGGER.warn("Repaired {} missing concurrency key wakeups", repairedCount);
                            }
                            return repairedCount;
                        })
                        .one()
                > 0;
    }
}
