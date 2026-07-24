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

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.cache.api.NoopCacheManager;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.migration.MigrationExecutor;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.memory.MemoryFileStorage;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.secret.TestSecretManager;
import org.dependencytrack.secret.management.SecretManager;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.net.http.HttpClient;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@Testcontainers
class DexEngineInitializerTest {

    @Container
    private final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"));
    private PGSimpleDataSource dataSource;
    private DataSourceRegistry dataSourceRegistry;
    private DexEngineInitializer initializer;

    @BeforeEach
    void beforeEach() {
        dataSource = new PGSimpleDataSource();
        dataSource.setUrl(postgresContainer.getJdbcUrl());
        dataSource.setUser(postgresContainer.getUsername());
        dataSource.setPassword(postgresContainer.getPassword());
        new MigrationExecutor(dataSource).execute();
    }

    @AfterEach
    void afterEach() {
        if (initializer != null) {
            initializer.contextDestroyed(null);
        }
        if (dataSourceRegistry != null) {
            dataSourceRegistry.closeAll();
        }
    }

    @Test
    void shouldLoadPolicyEvaluationMaxDurationFromApplicationProperties() {
        final var config = new SmallRyeConfigBuilder()
                .addDefaultSources()
                .build();

        assertThat(config.getValue(ConfigKeys.POLICY_EVALUATION_MAX_DURATION_MS, long.class))
                .isEqualTo(600_000L);
    }

    @Test
    void shouldStartEngine() throws Exception {
        final var config = new SmallRyeConfigBuilder()
                .addDefaultSources()
                .withSources(configSource(Map.of(
                        "dt.datasource.default.url", postgresContainer.getJdbcUrl(),
                        "dt.datasource.default.username", postgresContainer.getUsername(),
                        "dt.datasource.default.password", postgresContainer.getPassword())))
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);
        final var cacheManager = new NoopCacheManager();
        final var healthCheckRegistry = new HealthCheckRegistry(Collections.emptyList());
        final var secretManager = new TestSecretManager();

        final var servletContextMock = mock(ServletContext.class);
        doReturn(cacheManager)
                .when(servletContextMock).getAttribute(eq(CacheManager.class.getName()));
        doReturn(new MemoryFileStorage())
                .when(servletContextMock).getAttribute(eq(FileStorage.class.getName()));
        doReturn(new PluginManager(config, cacheManager, secretManager::getSecretValue,
                JdbiFactory.createLocalJdbi(dataSource),
                HttpClient.newHttpClient(), Collections.emptyList()))
                .when(servletContextMock).getAttribute(eq(PluginManager.class.getName()));
        doReturn(secretManager)
                .when(servletContextMock).getAttribute(eq(SecretManager.class.getName()));

        initializer = new DexEngineInitializer(config, dataSourceRegistry, new SimpleMeterRegistry(), healthCheckRegistry);
        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        final var engineCaptor = ArgumentCaptor.forClass(DexEngine.class);
        verify(servletContextMock).setAttribute(
                eq(DexEngine.class.getName()),
                engineCaptor.capture());

        assertThat(healthCheckRegistry.getChecks())
                .satisfiesExactly(healthCheck -> assertThat(healthCheck).isInstanceOf(DexEngineHealthCheck.class));

        final DexEngine engine = engineCaptor.getValue();
        assertThat(engine).isNotNull();
        engine.close();
    }

    private static ConfigSource configSource(Map<String, String> properties) {
        return new ConfigSource() {
            @Override
            public Map<String, String> getProperties() {
                return properties;
            }

            @Override
            public Set<String> getPropertyNames() {
                return properties.keySet();
            }

            @Override
            public String getValue(String propertyName) {
                return properties.get(propertyName);
            }

            @Override
            public String getName() {
                return DexEngineInitializerTest.class.getSimpleName();
            }

            @Override
            public int getOrdinal() {
                return 500;
            }
        };
    }

}
