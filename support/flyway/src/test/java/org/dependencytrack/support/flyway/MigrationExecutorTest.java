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
package org.dependencytrack.support.flyway;

import org.flywaydb.core.api.exception.FlywayValidateException;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers
class MigrationExecutorTest {

    private static final String STAGE1_MIGRATIONS_LOCATION = "classpath:org/dependencytrack/support/flyway/outoforder/stage1";
    private static final String STAGE2_MIGRATIONS_LOCATION = "classpath:org/dependencytrack/support/flyway/outoforder/stage2";
    private static final String BASELINE_SCHEMA_VERSION = "0";

    @Container
    private final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"))
                    .withCommand("postgres", "-c", "fsync=off", "-c", "full_page_writes=off")
                    .withTmpFs(Map.of("/var/lib/postgresql/data", "rw"));

    @Test
    void shouldApplyMigrationsOutOfOrder() throws Exception {
        final DataSource dataSource = createDataSource();

        new MigrationExecutor(dataSource, BASELINE_SCHEMA_VERSION, STAGE1_MIGRATIONS_LOCATION, null, null, true).execute();

        new MigrationExecutor(dataSource, BASELINE_SCHEMA_VERSION, STAGE2_MIGRATIONS_LOCATION, null, null, true).execute();

        final Map<String, Integer> ranksByVersion = readSchemaHistoryRanks();
        assertThat(ranksByVersion).containsKeys("001", "002", "003");
        assertThat(ranksByVersion.get("002")).isGreaterThan(ranksByVersion.get("003"));
    }

    @Test
    void shouldRejectOutOfOrderMigrationWhenOutOfOrderIsDisabled() {
        final DataSource dataSource = createDataSource();

        new MigrationExecutor(dataSource, BASELINE_SCHEMA_VERSION, STAGE1_MIGRATIONS_LOCATION, null, null, false).execute();

        assertThatThrownBy(() ->
                new MigrationExecutor(dataSource, BASELINE_SCHEMA_VERSION, STAGE2_MIGRATIONS_LOCATION, null, null, false).execute())
                .isInstanceOf(FlywayValidateException.class)
                .hasMessageContaining("Detected resolved migration not applied to database: 002");
    }

    @Test
    void shouldExecuteMigrationIdempotently() {
        final DataSource dataSource = createDataSource();
        new MigrationExecutor(dataSource, BASELINE_SCHEMA_VERSION, STAGE1_MIGRATIONS_LOCATION, null, null, true).execute();
        new MigrationExecutor(dataSource, BASELINE_SCHEMA_VERSION, STAGE1_MIGRATIONS_LOCATION, null, null, true).execute();
    }

    private DataSource createDataSource() {
        final var dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        return dataSource;
    }

    private Map<String, Integer> readSchemaHistoryRanks() throws SQLException {
        final var result = new LinkedHashMap<String, Integer>();
        try (final Connection connection = postgresContainer.createConnection("");
             final Statement statement = connection.createStatement();
             final ResultSet rs = statement.executeQuery("""
                     SELECT version
                          , installed_rank
                       FROM flyway_schema_history
                      WHERE version IS NOT NULL
                     """)) {
            while (rs.next()) {
                result.put(
                        rs.getString("version"),
                        rs.getInt("installed_rank"));
            }
        }

        return result;
    }

}
