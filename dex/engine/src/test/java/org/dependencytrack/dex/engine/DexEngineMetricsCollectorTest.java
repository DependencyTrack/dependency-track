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
import io.micrometer.core.instrument.search.MeterNotFoundException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.common.pagination.SimplePageTokenEncoder;
import org.dependencytrack.dex.engine.persistence.jdbi.JdbiFactory;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.awaitility.Awaitility.await;

@Testcontainers
class DexEngineMetricsCollectorTest {

    @Container
    private static final PostgresTestContainer postgresContainer = new PostgresTestContainer();

    private Jdbi jdbi;
    private MeterRegistry meterRegistry;

    @BeforeEach
    void beforeEach() {
        postgresContainer.truncateTables();

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        dataSource.setDatabaseName(postgresContainer.getDatabaseName());

        jdbi = JdbiFactory.create(dataSource, new SimplePageTokenEncoder());
        meterRegistry = new SimpleMeterRegistry();
    }

    @Test
    void shouldCollectRunCountByWorkflowNameAndStatus() {
        jdbi.useHandle(handle -> {
            handle.execute("select dex_create_workflow_task_queue('default', cast(100 as smallint))");
            handle.execute("""
                    insert into dex_workflow_run(id, workflow_name, workflow_version, task_queue_name, status, created_at)
                    values ('a0000000-0000-0000-0000-000000000001', 'wf-a', 1, 'default', 'RUNNING', now())
                         , ('a0000000-0000-0000-0000-000000000002', 'wf-a', 1, 'default', 'RUNNING', now())
                         , ('a0000000-0000-0000-0000-000000000003', 'wf-a', 1, 'default', 'CREATED', now())
                         , ('b0000000-0000-0000-0000-000000000001', 'wf-b', 1, 'default', 'COMPLETED', now())
                         , ('b0000000-0000-0000-0000-000000000002', 'wf-b', 1, 'default', 'FAILED', now())
                    """);
        });

        try (final var collector = new DexEngineMetricsCollector(
                jdbi, Duration.ZERO, Duration.ofMillis(50), meterRegistry)) {
            collector.start();

            await("Collection")
                    .atMost(Duration.ofSeconds(5))
                    .ignoreException(MeterNotFoundException.class)
                    .untilAsserted(() -> {
                        assertThat(meterRegistry.get("dt.dex.engine.workflow.runs.current")
                                .tag("workflowName", "wf-a").tag("status", "running")
                                .gauge().value()).isEqualTo(2.0);
                        assertThat(meterRegistry.get("dt.dex.engine.workflow.runs.current")
                                .tag("workflowName", "wf-a").tag("status", "created")
                                .gauge().value()).isEqualTo(1.0);
                        assertThat(meterRegistry.get("dt.dex.engine.workflow.runs.current")
                                .tag("workflowName", "wf-b").tag("status", "completed")
                                .gauge().value()).isEqualTo(1.0);
                        assertThat(meterRegistry.get("dt.dex.engine.workflow.runs.current")
                                .tag("workflowName", "wf-b").tag("status", "failed")
                                .gauge().value()).isEqualTo(1.0);
                    });
        }
    }

    @Test
    void shouldOverwriteStaleRunCountStatuses() {
        jdbi.useHandle(handle -> {
            handle.execute("select dex_create_workflow_task_queue('default', cast(100 as smallint))");
            handle.execute("""
                    insert into dex_workflow_run(id, workflow_name, workflow_version, task_queue_name, status, created_at)
                    values ('a0000000-0000-0000-0000-000000000001', 'wf-a', 1, 'default', 'CREATED', now())
                         , ('a0000000-0000-0000-0000-000000000002', 'wf-a', 1, 'default', 'CREATED', now())
                    """);
        });

        try (final var collector = new DexEngineMetricsCollector(
                jdbi, Duration.ZERO, Duration.ofMillis(50), meterRegistry)) {
            collector.start();

            await("First Collection")
                    .atMost(Duration.ofSeconds(5))
                    .ignoreException(MeterNotFoundException.class)
                    .untilAsserted(() -> assertThat(meterRegistry
                            .get("dt.dex.engine.workflow.runs.current")
                            .tag("workflowName", "wf-a")
                            .tag("status", "created")
                            .gauge()
                            .value())
                            .isEqualTo(2.0));

            jdbi.useHandle(handle -> handle.execute("""
                    update dex_workflow_run set status = 'COMPLETED', completed_at = now()
                    """));

            await("Second Collection")
                    .atMost(Duration.ofSeconds(5))
                    .ignoreException(MeterNotFoundException.class)
                    .untilAsserted(() -> {
                        assertThat(meterRegistry
                                .get("dt.dex.engine.workflow.runs.current")
                                .tag("workflowName", "wf-a")
                                .tag("status", "completed")
                                .gauge()
                                .value())
                                .isEqualTo(2.0);

                        assertThat(meterRegistry
                                .find("dt.dex.engine.workflow.runs.current")
                                .tag("workflowName", "wf-a")
                                .tag("status", "created")
                                .gauge())
                                .isNull();
                    });
        }
    }

    @Test
    void shouldCollectWorkflowTaskQueueCapacityAndDepth() {
        jdbi.useHandle(handle -> {
            handle.execute("select dex_create_workflow_task_queue('queue-a', cast(50 as smallint))");
            handle.execute("select dex_create_workflow_task_queue('queue-b', cast(75 as smallint))");

            handle.execute("""
                    insert into dex_workflow_run(id, workflow_name, workflow_version, task_queue_name, status, created_at)
                    values ('a0000000-0000-0000-0000-000000000001', 'wf-a', 1, 'queue-a', 'CREATED', now())
                         , ('a0000000-0000-0000-0000-000000000002', 'wf-a', 1, 'queue-a', 'CREATED', now())
                         , ('b0000000-0000-0000-0000-000000000001', 'wf-b', 1, 'queue-b', 'CREATED', now())
                    """);

            handle.execute("""
                    insert into dex_workflow_task(queue_name, workflow_run_id, workflow_name, priority, created_at)
                    values ('queue-a', 'a0000000-0000-0000-0000-000000000001', 'wf-a', 0, now())
                         , ('queue-a', 'a0000000-0000-0000-0000-000000000002', 'wf-a', 0, now())
                         , ('queue-b', 'b0000000-0000-0000-0000-000000000001', 'wf-b', 0, now())
                    """);
        });

        try (final var collector = new DexEngineMetricsCollector(
                jdbi, Duration.ZERO, Duration.ofMillis(50), meterRegistry)) {
            collector.start();

            await("Collection")
                    .atMost(Duration.ofSeconds(5))
                    .ignoreException(MeterNotFoundException.class)
                    .untilAsserted(() -> {
                        assertThat(meterRegistry.get("dt.dex.engine.workflow.task.queue.capacity")
                                .tag("queueName", "queue-a")
                                .gauge().value()).isEqualTo(50.0);
                        assertThat(meterRegistry.get("dt.dex.engine.workflow.task.queue.capacity")
                                .tag("queueName", "queue-b")
                                .gauge().value()).isEqualTo(75.0);

                        assertThat(meterRegistry.get("dt.dex.engine.workflow.task.queue.depth")
                                .tag("queueName", "queue-a")
                                .gauge().value()).isEqualTo(2.0);
                        assertThat(meterRegistry.get("dt.dex.engine.workflow.task.queue.depth")
                                .tag("queueName", "queue-b")
                                .gauge().value()).isEqualTo(1.0);
                    });
        }
    }

    @Test
    void shouldCollectActivityTaskQueueCapacityAndDepth() {
        jdbi.useHandle(handle -> {
            handle.execute("select dex_create_workflow_task_queue('default', cast(100 as smallint))");
            handle.execute("select dex_create_activity_task_queue('act-queue-a', cast(30 as smallint))");
            handle.execute("select dex_create_activity_task_queue('act-queue-b', cast(60 as smallint))");

            handle.execute("""
                    insert into dex_workflow_run(id, workflow_name, workflow_version, task_queue_name, status, created_at)
                    values ('a0000000-0000-0000-0000-000000000001', 'wf-a', 1, 'default', 'RUNNING', now())
                         , ('a0000000-0000-0000-0000-000000000002', 'wf-a', 1, 'default', 'RUNNING', now())
                    """);

            handle.execute("""
                    insert into dex_activity_task(queue_name, workflow_run_id, created_event_id, activity_name, priority, retry_policy, status, created_at)
                    values ('act-queue-a', 'a0000000-0000-0000-0000-000000000001', 1, 'act-a', 0, ''::bytea, 'QUEUED', now())
                         , ('act-queue-a', 'a0000000-0000-0000-0000-000000000001', 2, 'act-a', 0, ''::bytea, 'QUEUED', now())
                         , ('act-queue-a', 'a0000000-0000-0000-0000-000000000002', 1, 'act-a', 0, ''::bytea, 'CREATED', now())
                         , ('act-queue-b', 'a0000000-0000-0000-0000-000000000002', 2, 'act-b', 0, ''::bytea, 'QUEUED', now())
                    """);
        });

        try (final var collector = new DexEngineMetricsCollector(
                jdbi, Duration.ZERO, Duration.ofMillis(50), meterRegistry)) {
            collector.start();

            await("Collection")
                    .atMost(Duration.ofSeconds(5))
                    .ignoreException(MeterNotFoundException.class)
                    .untilAsserted(() -> {
                        assertThat(meterRegistry.get("dt.dex.engine.activity.task.queue.capacity")
                                .tag("queueName", "act-queue-a")
                                .gauge().value()).isEqualTo(30.0);
                        assertThat(meterRegistry.get("dt.dex.engine.activity.task.queue.capacity")
                                .tag("queueName", "act-queue-b")
                                .gauge().value()).isEqualTo(60.0);

                        assertThat(meterRegistry.get("dt.dex.engine.activity.task.queue.depth")
                                .tag("queueName", "act-queue-a")
                                .gauge().value()).isEqualTo(2.0);
                        assertThat(meterRegistry.get("dt.dex.engine.activity.task.queue.depth")
                                .tag("queueName", "act-queue-b")
                                .gauge().value()).isEqualTo(1.0);
                    });
        }
    }

    @Test
    void shouldCollectActivityBacklog() {
        jdbi.useHandle(handle -> {
            handle.execute("select dex_create_workflow_task_queue('default', cast(100 as smallint))");
            handle.execute("select dex_create_activity_task_queue('act-queue-a', cast(30 as smallint))");
            handle.execute("select dex_create_activity_task_queue('act-queue-b', cast(60 as smallint))");
            handle.execute("select dex_create_activity_task_queue('act-queue-empty', cast(10 as smallint))");

            handle.execute("""
                    insert into dex_workflow_run(id, workflow_name, workflow_version, task_queue_name, status, created_at)
                    values ('a0000000-0000-0000-0000-000000000001', 'wf-a', 1, 'default', 'RUNNING', now())
                         , ('a0000000-0000-0000-0000-000000000002', 'wf-a', 1, 'default', 'RUNNING', now())
                    """);
            
            handle.execute("""
                    insert into dex_activity_task(queue_name, workflow_run_id, created_event_id, activity_name, priority, retry_policy, status, visible_from, created_at)
                    values ('act-queue-a', 'a0000000-0000-0000-0000-000000000001', 1, 'act-a', 0, ''::bytea, 'CREATED', now() - interval '1 second', now())
                         , ('act-queue-a', 'a0000000-0000-0000-0000-000000000001', 2, 'act-a', 0, ''::bytea, 'CREATED', now() - interval '2 seconds', now())
                         , ('act-queue-a', 'a0000000-0000-0000-0000-000000000001', 3, 'act-a', 0, ''::bytea, 'CREATED', now() + interval '1 hour', now())
                         , ('act-queue-a', 'a0000000-0000-0000-0000-000000000002', 1, 'act-a', 0, ''::bytea, 'QUEUED', now(), now())
                         , ('act-queue-b', 'a0000000-0000-0000-0000-000000000002', 2, 'act-b', 0, ''::bytea, 'CREATED', now(), now())
                    """);
        });

        try (final var collector = new DexEngineMetricsCollector(
                jdbi, Duration.ZERO, Duration.ofMillis(50), meterRegistry)) {
            collector.start();

            await("Collection")
                    .atMost(Duration.ofSeconds(5))
                    .ignoreException(MeterNotFoundException.class)
                    .untilAsserted(() -> {
                        assertThat(meterRegistry.get("dt.dex.engine.activity.task.queue.backlog")
                                .tag("queueName", "act-queue-a")
                                .gauge().value()).isEqualTo(2.0);
                        assertThat(meterRegistry.get("dt.dex.engine.activity.task.queue.backlog")
                                .tag("queueName", "act-queue-b")
                                .gauge().value()).isEqualTo(1.0);
                        assertThat(meterRegistry.find("dt.dex.engine.activity.task.queue.backlog")
                                .tag("queueName", "act-queue-empty")
                                .gauge()).isNull();
                    });
        }
    }

    @Test
    void shouldCollectActivityBacklogAge() {
        jdbi.useHandle(handle -> {
            handle.execute("select dex_create_workflow_task_queue('default', cast(100 as smallint))");
            handle.execute("select dex_create_activity_task_queue('act-queue-a', cast(30 as smallint))");
            handle.execute("select dex_create_activity_task_queue('act-queue-b', cast(60 as smallint))");

            handle.execute("""
                    insert into dex_workflow_run(id, workflow_name, workflow_version, task_queue_name, status, created_at)
                    values ('a0000000-0000-0000-0000-000000000001', 'wf-a', 1, 'default', 'RUNNING', now())
                    """);

            handle.execute("""
                    insert into dex_activity_task(queue_name, workflow_run_id, created_event_id, activity_name, priority, retry_policy, status, visible_from, created_at)
                    values ('act-queue-a', 'a0000000-0000-0000-0000-000000000001', 1, 'act-a', 0, ''::bytea, 'CREATED', now() - interval '5 seconds', now())
                         , ('act-queue-a', 'a0000000-0000-0000-0000-000000000001', 2, 'act-a', 0, ''::bytea, 'CREATED', now() - interval '1 second', now())
                         , ('act-queue-b', 'a0000000-0000-0000-0000-000000000001', 3, 'act-b', 0, ''::bytea, 'CREATED', now() - interval '2 seconds', now())
                    """);
        });

        try (final var collector = new DexEngineMetricsCollector(
                jdbi, Duration.ZERO, Duration.ofMillis(50), meterRegistry)) {
            collector.start();

            await("Collection")
                    .atMost(Duration.ofSeconds(5))
                    .ignoreException(MeterNotFoundException.class)
                    .untilAsserted(() -> {
                        assertThat(meterRegistry.get("dt.dex.engine.activity.task.queue.backlog.age")
                                .tag("queueName", "act-queue-a")
                                .gauge().value()).isCloseTo(5.0, within(2.0));
                        assertThat(meterRegistry.get("dt.dex.engine.activity.task.queue.backlog.age")
                                .tag("queueName", "act-queue-b")
                                .gauge().value()).isCloseTo(2.0, within(2.0));
                    });
        }
    }

    @Test
    void shouldHandleEmptyDatabase() {
        try (final var collector = new DexEngineMetricsCollector(
                jdbi, Duration.ZERO, Duration.ofMillis(50), meterRegistry)) {
            collector.start();

            await("Collection")
                    .during(Duration.ofMillis(200))
                    .atMost(Duration.ofSeconds(5))
                    .ignoreException(MeterNotFoundException.class)
                    .untilAsserted(() -> {
                        assertThat(meterRegistry.find("dt.dex.engine.workflow.runs.current").gauge()).isNull();
                        assertThat(meterRegistry.find("dt.dex.engine.workflow.task.queue.depth").gauge()).isNull();
                        assertThat(meterRegistry.find("dt.dex.engine.activity.task.queue.depth").gauge()).isNull();
                        assertThat(meterRegistry.find("dt.dex.engine.activity.task.queue.backlog").gauge()).isNull();
                        assertThat(meterRegistry.find("dt.dex.engine.activity.task.queue.backlog.age").gauge()).isNull();
                    });
        }
    }

}
