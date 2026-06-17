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

import com.zaxxer.hikari.HikariDataSource;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@Testcontainers
class DataSourceRegistryTest {

    @Container
    private static final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer("postgres:14-alpine");

    private DataSourceRegistry registry;

    @BeforeEach
    void beforeEach() {
        final Config config = new SmallRyeConfigBuilder()
                .withSources(new MemoryConfigSource())
                .withCustomizers(new ConfigBuilderCustomizer())
                .build();

        registry = new DataSourceRegistry(config);
    }

    @AfterEach
    void afterEach() {
        if (registry != null) {
            registry.closeAll();
        }

        MemoryConfigSource.clear();
    }

    @Test
    void shouldCreateSimpleDataSourceWhenPoolIsDisabled() {
        MemoryConfigSource.setProperties(Map.ofEntries(
                Map.entry("dt.datasource.url", postgresContainer.getJdbcUrl()),
                Map.entry("dt.datasource.username", postgresContainer.getUsername()),
                Map.entry("dt.datasource.password", postgresContainer.getPassword()),
                Map.entry("dt.datasource.pool.enabled", "false")));

        final DataSource dataSource = registry.getDefault();
        assertThat(dataSource).isInstanceOf(PGSimpleDataSource.class);
    }

    @Test
    void shouldCreatePooledDataSourceWhenPoolIsEnabled() {
        MemoryConfigSource.setProperties(Map.ofEntries(
                Map.entry("dt.datasource.url", postgresContainer.getJdbcUrl()),
                Map.entry("dt.datasource.username", postgresContainer.getUsername()),
                Map.entry("dt.datasource.password", postgresContainer.getPassword()),
                Map.entry("dt.datasource.pool.enabled", "true"),
                Map.entry("dt.datasource.pool.max-size", "2"),
                Map.entry("dt.datasource.pool.min-idle", "1")));

        final DataSource dataSource = registry.getDefault();
        assertThat(dataSource).isInstanceOf(HikariDataSource.class);

        final var hikariDataSource = (HikariDataSource) dataSource;
        assertThat(hikariDataSource.getPoolName()).isEqualTo("default");
        assertThat(hikariDataSource.getMaximumPoolSize()).isEqualTo(2);
        assertThat(hikariDataSource.getMinimumIdle()).isEqualTo(1);
    }

    @Test
    void shouldCacheDataSource() {
        MemoryConfigSource.setProperties(Map.ofEntries(
                Map.entry("dt.datasource.url", postgresContainer.getJdbcUrl()),
                Map.entry("dt.datasource.username", postgresContainer.getUsername()),
                Map.entry("dt.datasource.password", postgresContainer.getPassword()),
                Map.entry("dt.datasource.pool.enabled", "false")));

        final DataSource dataSourceA = registry.getDefault();
        final DataSource dataSourceB = registry.get("default");
        assertThat(dataSourceA).isSameAs(dataSourceB);
    }

    @Test
    void shouldSupportNamedDataSource() {
        MemoryConfigSource.setProperties(Map.ofEntries(
                Map.entry("dt.datasource.foo.url", postgresContainer.getJdbcUrl()),
                Map.entry("dt.datasource.foo.username", postgresContainer.getUsername()),
                Map.entry("dt.datasource.foo.password", postgresContainer.getPassword()),
                Map.entry("dt.datasource.foo.pool.enabled", "false")));

        final DataSource dataSource = registry.get("foo");
        assertThat(dataSource).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "dt.datasource.url",
            "dt.datasource.pool.max-size",
            "dt.datasource.pool.min-idle"
    })
    void shouldThrowWhenRequiredPropertiesAreMissing(final String propertyToOmit) {
        final var validConfig = new HashMap<>(Map.ofEntries(
                Map.entry("dt.datasource.url", postgresContainer.getJdbcUrl()),
                Map.entry("dt.datasource.username", postgresContainer.getUsername()),
                Map.entry("dt.datasource.password", postgresContainer.getPassword()),
                Map.entry("dt.datasource.pool.enabled", "true"),
                Map.entry("dt.datasource.pool.max-size", "2"),
                Map.entry("dt.datasource.pool.min-idle", "0")));

        validConfig.remove(propertyToOmit);

        MemoryConfigSource.setProperties(validConfig);

        assertThatExceptionOfType(NoSuchElementException.class)
                .isThrownBy(() -> registry.getDefault());
    }

}