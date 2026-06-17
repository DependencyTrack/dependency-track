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
package org.dependencytrack.dex;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.init.InitTaskContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@Testcontainers
class DexEngineDatabaseMigrationInitTaskTest {

    @Container
    private final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"));
    private DataSourceRegistry dataSourceRegistry;

    @AfterEach
    void afterEach() {
        if (dataSourceRegistry != null) {
            dataSourceRegistry.closeAll();
        }
    }

    @Test
    void shouldUseEngineMigrationDataSourceWhenConfigured() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("dt.datasource.foo.url", postgresContainer.getJdbcUrl()),
                        Map.entry("dt.datasource.foo.username", postgresContainer.getUsername()),
                        Map.entry("dt.datasource.foo.password", postgresContainer.getPassword()),
                        Map.entry("dt.dex-engine.migration.datasource.name", "foo")))
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);

        new DexEngineDatabaseMigrationInitTask(dataSourceRegistry)
                .execute(new InitTaskContext(config, null));

        assertMigrationExecuted(true);
    }

    @Test
    void shouldUseEngineDataSourceWhenConfigured() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("dt.datasource.foo.url", postgresContainer.getJdbcUrl()),
                        Map.entry("dt.datasource.foo.username", postgresContainer.getUsername()),
                        Map.entry("dt.datasource.foo.password", postgresContainer.getPassword()),
                        Map.entry("dt.dex-engine.datasource.name", "foo")))
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);

        new DexEngineDatabaseMigrationInitTask(dataSourceRegistry)
                .execute(new InitTaskContext(config, null));

        assertMigrationExecuted(true);
    }

    @Test
    void shouldThrowWhenNoDataSourceIsConfigured() throws Exception {
        final var config = new SmallRyeConfigBuilder().build();

        dataSourceRegistry = new DataSourceRegistry(config);

        final var initTask = new DexEngineDatabaseMigrationInitTask(dataSourceRegistry);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> initTask.execute(new InitTaskContext(config, null)))
                .withMessage("No datasource name configured");

        assertMigrationExecuted(false);
    }

    private void assertMigrationExecuted(final boolean expectExecuted) throws SQLException {
        try (final Connection connection = postgresContainer.createConnection("");
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT "table_name"
                       FROM "information_schema"."tables"
                      WHERE "table_schema" NOT IN ('pg_catalog', 'information_schema')
                     """)) {
            final ResultSet rs = ps.executeQuery();

            assertThat(rs.next()).isEqualTo(expectExecuted);
        }
    }

}