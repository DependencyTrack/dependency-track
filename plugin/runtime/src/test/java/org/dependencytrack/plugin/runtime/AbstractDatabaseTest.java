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
package org.dependencytrack.plugin.runtime;

import org.dependencytrack.migration.MigrationExecutor;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.postgres.PostgresPlugin;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.Map;

@Testcontainers
abstract class AbstractDatabaseTest {

    @Container
    private static final PostgreSQLContainer POSTGRES_CONTAINER =
            new PostgreSQLContainer("postgres:14-alpine")
                    .withCommand("postgres", "-c", "fsync=off", "-c", "full_page_writes=off")
                    .withUrlParam("reWriteBatchedInserts", "true")
                    .withTmpFs(Map.of("/var/lib/postgresql/data", "rw"));

    protected static Jdbi jdbi;

    @BeforeAll
    static void initDatabase() {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(POSTGRES_CONTAINER.getJdbcUrl());
        dataSource.setUser(POSTGRES_CONTAINER.getUsername());
        dataSource.setPassword(POSTGRES_CONTAINER.getPassword());

        new MigrationExecutor(dataSource).execute();

        jdbi = Jdbi
                .create(dataSource)
                .installPlugin(new PostgresPlugin());
    }

    @BeforeEach
    void truncateExtensionTables() {
        jdbi.useHandle(handle -> {
            handle.execute("""
                    TRUNCATE TABLE "EXTENSION_RUNTIME_CONFIG" CASCADE
                    """);
            handle.execute("""
                    TRUNCATE TABLE "EXTENSION_KV_STORE" CASCADE
                    """);
        });
    }

}
