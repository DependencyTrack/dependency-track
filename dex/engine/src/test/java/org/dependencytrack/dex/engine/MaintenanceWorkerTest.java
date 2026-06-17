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

import org.dependencytrack.common.pagination.SimplePageTokenEncoder;
import org.dependencytrack.dex.engine.persistence.jdbi.JdbiFactory;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@Testcontainers
class MaintenanceWorkerTest {

    @Container
    private static final PostgresTestContainer postgresContainer = new PostgresTestContainer();

    private Jdbi jdbi;

    @BeforeEach
    void beforeEach() {
        postgresContainer.truncateTables();

        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        dataSource.setDatabaseName(postgresContainer.getDatabaseName());

        jdbi = JdbiFactory.create(dataSource, new SimplePageTokenEncoder());
    }

    @Test
    void test() {
        jdbi.useHandle(handle -> {
            handle.execute("""
                    select dex_create_workflow_task_queue('default', cast(1 as smallint))
                    """);

            handle.execute("""
                    insert into dex_workflow_run(id, workflow_name, workflow_version, task_queue_name, status, created_at, completed_at)
                    values ('f6650566-5739-4880-a54d-863bbf705d3f', 'foo', 1, 'default', 'COMPLETED', now() - '10 days'::interval, now() - '5 days'::interval)
                         , ('c717aa74-0255-4b5a-a1b2-c641bf36f407', 'bar', 2, 'default', 'FAILED', now() - '9 days'::interval, now() - '4 days'::interval)
                         , ('e01d0fe8-f972-474c-bc70-ba8ce4bc4351', 'bar', 2, 'default', 'RUNNING', now() - '9 days'::interval, null)
                         , ('7afa067a-4e49-4a29-98e2-d199c59bd3ca', 'baz', 3, 'default', 'CANCELLED', now() - '8 days'::interval, now() - '3 days'::interval)
                         , ('4f8fe08f-6263-4beb-a515-8a0b4e56d9e8', 'qux', 4, 'default', 'COMPLETED', now() - '7 days'::interval, now() - '2 days'::interval)
                    """);
        });

        final var worker = new MaintenanceWorker(
                jdbi,
                /* leadershipSupplier */ () -> true,
                /* runRetentionDuration */ Duration.ofDays(3),
                /* runRetentionBatchSize */ 10,
                /* initialDelay */ Duration.ZERO,
                /* interval */ Duration.ofMillis(100));

        try (worker) {
            worker.start();

            await()
                    .atMost(Duration.ofSeconds(1))
                    .untilAsserted(() -> {
                        final List<String> remainingIds = jdbi.withHandle(
                                handle -> handle.createQuery("select id from dex_workflow_run").mapTo(String.class).list());
                        assertThat(remainingIds).containsExactlyInAnyOrder(
                                "e01d0fe8-f972-474c-bc70-ba8ce4bc4351",
                                "4f8fe08f-6263-4beb-a515-8a0b4e56d9e8");
                    });
        }
    }

}