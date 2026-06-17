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

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.MultiGauge;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

final class DexEngineMetricsCollector implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DexEngineMetricsCollector.class);
    private static final int ACTIVITY_TASK_QUEUE_BACKLOG_COUNT_CAP = 10_000;

    private final Jdbi jdbi;
    private final Duration initialDelay;
    private final Duration interval;
    private final MultiGauge runCountGauge;
    private final MultiGauge workflowTaskQueueCapacityGauge;
    private final MultiGauge workflowTaskQueueDepthGauge;
    private final MultiGauge activityTaskQueueCapacityGauge;
    private final MultiGauge activityTaskQueueDepthGauge;
    private final MultiGauge activityTaskQueueBacklogGauge;
    private final MultiGauge activityTaskQueueBacklogAgeGauge;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private @Nullable ScheduledExecutorService executor;

    DexEngineMetricsCollector(Jdbi jdbi, Duration initialDelay, Duration interval, MeterRegistry meterRegistry) {
        this.jdbi = jdbi;
        this.initialDelay = initialDelay;
        this.interval = interval;
        this.runCountGauge = MultiGauge
                .builder("dt.dex.engine.workflow.runs.current")
                .description("Current number of workflow runs by name and status")
                .register(meterRegistry);
        this.workflowTaskQueueCapacityGauge = MultiGauge
                .builder("dt.dex.engine.workflow.task.queue.capacity")
                .description("Capacity of workflow task queues by name")
                .register(meterRegistry);
        this.workflowTaskQueueDepthGauge = MultiGauge
                .builder("dt.dex.engine.workflow.task.queue.depth")
                .description("Depth of workflow task queues by name")
                .register(meterRegistry);
        this.activityTaskQueueCapacityGauge = MultiGauge
                .builder("dt.dex.engine.activity.task.queue.capacity")
                .description("Capacity of activity task queues by name")
                .register(meterRegistry);
        this.activityTaskQueueDepthGauge = MultiGauge
                .builder("dt.dex.engine.activity.task.queue.depth")
                .description("Depth of activity task queues by name")
                .register(meterRegistry);
        this.activityTaskQueueBacklogGauge = MultiGauge
                .builder("dt.dex.engine.activity.task.queue.backlog")
                .description("Approximate count of unqueued, ready-to-schedule activity tasks per queue (capped at %d)".formatted(ACTIVITY_TASK_QUEUE_BACKLOG_COUNT_CAP))
                .register(meterRegistry);
        this.activityTaskQueueBacklogAgeGauge = MultiGauge
                .builder("dt.dex.engine.activity.task.queue.backlog.age")
                .description("Age of the oldest unqueued, ready-to-schedule activity task per queue")
                .baseUnit("seconds")
                .register(meterRegistry);
    }

    void start() {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("Already started");
        }

        executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name(getClass().getSimpleName())
                        .factory());
        executor.scheduleAtFixedRate(
                () -> {
                    try {
                        collectMetrics();
                    } catch (RuntimeException e) {
                        LOGGER.error("Failed to collect metrics", e);
                    }
                },
                initialDelay.toMillis(),
                interval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (!running.compareAndSet(true, false)) {
            throw new IllegalStateException("Already stopped");
        }

        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                LOGGER.warn("Interrupted while waiting for executor to stop", e);
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    private void collectMetrics() {
        collectRunMetrics();
        collectWorkflowTaskQueueMetrics();
        collectActivityTaskQueueMetrics();
        collectActivityTaskQueueBacklogMetrics();
    }

    private void collectRunMetrics() {
        final List<MultiGauge.Row<Number>> runStatusRows = jdbi.withHandle(
                handle -> handle
                        .createQuery("""
                                select workflow_name
                                     , status
                                     , count(*)
                                  from dex_workflow_run
                                 group by workflow_name
                                        , status
                                """)
                        .map((rs, _) -> MultiGauge.Row.of(
                                Tags.of(
                                        Tag.of("workflowName", rs.getString(1)),
                                        Tag.of("status", rs.getString(2).toLowerCase())),
                                rs.getLong(3)))
                        .list());
        runCountGauge.register(runStatusRows, /* overwrite */ true);
    }

    private void collectWorkflowTaskQueueMetrics() {
        final List<MultiGauge.Row<Number>> workflowTaskQueueCapacityRows = jdbi.withHandle(
                handle -> handle
                        .createQuery("""
                                select name
                                     , capacity
                                  from dex_workflow_task_queue
                                """)
                        .map((rs, _) -> MultiGauge.Row.of(
                                Tags.of(Tag.of("queueName", rs.getString(1))),
                                rs.getLong(2)))
                        .list());
        workflowTaskQueueCapacityGauge.register(workflowTaskQueueCapacityRows, /* overwrite */ true);

        final List<MultiGauge.Row<Number>> workflowTaskQueueDepthRows = jdbi.withHandle(
                handle -> handle
                        .createQuery("""
                                select queue_name
                                     , count(*)
                                  from dex_workflow_task
                                 group by queue_name
                                """)
                        .map((rs, _) -> MultiGauge.Row.of(
                                Tags.of(Tag.of("queueName", rs.getString(1))),
                                rs.getLong(2)))
                        .list());
        workflowTaskQueueDepthGauge.register(workflowTaskQueueDepthRows, /* overwrite */ true);
    }

    private void collectActivityTaskQueueMetrics() {
        final List<MultiGauge.Row<Number>> activityTaskQueueCapacityRows = jdbi.withHandle(
                handle -> handle
                        .createQuery("""
                                select name
                                     , capacity
                                  from dex_activity_task_queue
                                """)
                        .map((rs, _) -> MultiGauge.Row.of(
                                Tags.of(Tag.of("queueName", rs.getString(1))),
                                rs.getLong(2)))
                        .list());
        activityTaskQueueCapacityGauge.register(activityTaskQueueCapacityRows, /* overwrite */ true);

        final List<MultiGauge.Row<Number>> activityTaskQueueDepthRows = jdbi.withHandle(
                handle -> handle
                        .createQuery("""
                                select queue_name
                                     , count(*)
                                  from dex_activity_task
                                 where status = 'QUEUED'
                                 group by queue_name
                                """)
                        .map((rs, _) -> MultiGauge.Row.of(
                                Tags.of(Tag.of("queueName", rs.getString(1))),
                                rs.getLong(2)))
                        .list());
        activityTaskQueueDepthGauge.register(activityTaskQueueDepthRows, /* overwrite */ true);
    }

    public record TaskQueueBacklogRow(
            String queueName,
            long backlog,
            @Nullable Duration age) {
    }

    private void collectActivityTaskQueueBacklogMetrics() {
        final List<TaskQueueBacklogRow> rows = jdbi.withHandle(handle -> handle
                .createQuery("""
                        select tq.name as queue_name
                             , coalesce((
                                 select count(*)
                                   from (
                                     select 1
                                       from dex_activity_task
                                      where queue_name = tq.name
                                        and status != 'QUEUED'
                                        and visible_from <= now()
                                      limit :cap
                                   ) as capped
                               ), 0) as backlog
                             , now() - (
                                 select min(visible_from)
                                   from dex_activity_task
                                  where queue_name = tq.name
                                    and status != 'QUEUED'
                                    and visible_from <= now()
                               ) as age
                          from dex_activity_task_queue as tq
                         where tq.status = 'ACTIVE'
                        """)
                .bind("cap", ACTIVITY_TASK_QUEUE_BACKLOG_COUNT_CAP)
                .map(ConstructorMapper.of(TaskQueueBacklogRow.class))
                .list());

        // Drop queues with no eligible work, so that drained queues stop producing metrics.
        final var backlogRows = new ArrayList<MultiGauge.Row<Number>>(rows.size());
        final var ageRows = new ArrayList<MultiGauge.Row<Number>>(rows.size());
        for (final TaskQueueBacklogRow row : rows) {
            if (row.backlog() == 0 && row.age() == null) {
                continue;
            }

            final Tags tags = Tags.of("queueName", row.queueName());
            backlogRows.add(MultiGauge.Row.of(tags, row.backlog()));
            if (row.age() != null) {
                ageRows.add(MultiGauge.Row.of(tags, row.age().toMillis() / 1000.0));
            }
        }

        activityTaskQueueBacklogGauge.register(backlogRows, /* overwrite */ true);
        activityTaskQueueBacklogAgeGauge.register(ageRows, /* overwrite */ true);
    }

}
