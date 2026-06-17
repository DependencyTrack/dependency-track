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
package org.dependencytrack.persistence;

import org.dependencytrack.init.InitTaskContext;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class DatabaseMigrationInitTaskTest {

    private PostgreSQLContainer postgresContainer;
    private PGSimpleDataSource dataSource;
    private Jdbi jdbi;

    @BeforeEach
    public void setUp() {
        postgresContainer = new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"))
                .withCommand("postgres", "-c", "fsync=off", "-c", "full_page_writes=off")
                .withTmpFs(Map.of("/var/lib/postgresql/data", "rw"));
        postgresContainer.start();

        dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());

        MemoryConfigSource.setProperty("testcontainers.postgresql.jdbc-url", postgresContainer.getJdbcUrl());
        MemoryConfigSource.setProperty("testcontainers.postgresql.username", postgresContainer.getUsername());
        MemoryConfigSource.setProperty("testcontainers.postgresql.password", postgresContainer.getPassword());

        jdbi = Jdbi.create(dataSource);
    }

    @AfterEach
    public void tearDown() {
        MemoryConfigSource.clear();
        if (postgresContainer != null) {
            postgresContainer.stop();
        }
    }

    @Test
    public void test() throws Exception {
        MemoryConfigSource.setProperty("dt.datasource.url", "${testcontainers.postgresql.jdbc-url}");
        MemoryConfigSource.setProperty("dt.datasource.username", "${testcontainers.postgresql.username}");
        MemoryConfigSource.setProperty("dt.datasource.password", "${testcontainers.postgresql.password}");

        new DatabaseMigrationInitTask().execute(new InitTaskContext(ConfigProvider.getConfig(), dataSource));

        assertMigrationExecuted(/* expectExecuted */ true);
    }

    private void assertMigrationExecuted(final boolean expectExecuted) {
        final List<String> tableNames = jdbi.withHandle(handle -> handle.createQuery("""
                        SELECT "table_name"
                          FROM "information_schema"."tables"
                         WHERE "table_schema" NOT IN ('pg_catalog', 'information_schema')
                        """)
                .mapTo(String.class)
                .list());

        if (expectExecuted) {
            assertThat(tableNames).isNotEmpty();
        } else {
            assertThat(tableNames).isEmpty();
        }
    }

}