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
package org.dependencytrack.common.datasource;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class DataSourceHealthCheckTest {

    @Container
    private static final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer("postgres:14-alpine");

    private HikariDataSource dataSource;
    private DataSourceRegistry dataSourceRegistry;
    private HealthCheck healthCheck;

    @BeforeEach
    void beforeEach() {
        final var hikariConfig = new HikariConfig();
        hikariConfig.setJdbcUrl(postgresContainer.getJdbcUrl());
        hikariConfig.setUsername(postgresContainer.getUsername());
        hikariConfig.setPassword(postgresContainer.getPassword());
        hikariConfig.setMaximumPoolSize(1);
        hikariConfig.setMinimumIdle(1);
        dataSource = new HikariDataSource(hikariConfig);

        dataSourceRegistry = new DataSourceRegistry(new SmallRyeConfigBuilder().build());
        dataSourceRegistry.add("foo", dataSource);

        healthCheck = new DataSourceHealthCheck(dataSourceRegistry);
    }

    @AfterEach
    void afterEach() {
        if (dataSourceRegistry != null) {
            dataSourceRegistry.closeAll();
        }
    }

    @Test
    void shouldReportUpWhenConnectionCanBeAcquired() {
        final HealthCheckResponse response = healthCheck.call();

        assertThat(response.getName()).isEqualTo("dataSources");
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
        assertThat(response.getData()).isPresent();
        assertThat(response.getData().get()).containsExactly(Map.entry("foo", "UP"));
    }

    @Test
    void shouldReportDownWhenConnectionCanNotBeAcquired() {
        dataSource.close();

        final HealthCheckResponse response = healthCheck.call();

        assertThat(response.getName()).isEqualTo("dataSources");
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
        assertThat(response.getData()).isPresent();
        assertThat(response.getData().get()).containsExactly(Map.entry("foo", "DOWN"));
    }

}