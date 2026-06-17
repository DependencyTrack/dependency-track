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
package org.dependencytrack.cache.database;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.migration.MigrationExecutor;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class DatabaseCacheTest {

    @Container
    private static final PostgreSQLContainer postgresContainer =
            new PostgreSQLContainer("postgres:14-alpine");

    private static Config config;
    private static DataSourceRegistry dataSourceRegistry;
    private static DataSource dataSource;

    private CacheManager cacheManager;

    @BeforeAll
    static void beforeAll() throws Exception {
        config = new SmallRyeConfigBuilder()
                .withDefaultValues(Map.ofEntries(
                        Map.entry("dt.datasource.default.url", postgresContainer.getJdbcUrl()),
                        Map.entry("dt.datasource.default.username", postgresContainer.getUsername()),
                        Map.entry("dt.datasource.default.password", postgresContainer.getPassword()),
                        Map.entry("dt.cache.provider.database.datasource.name", "default")))
                .build();

        dataSourceRegistry = new DataSourceRegistry(config);
        dataSource = dataSourceRegistry.getDefault();

        new MigrationExecutor(dataSource).execute();
    }

    @BeforeEach
    void beforeEach() {
        final var cacheProviderFactory = new DatabaseCacheProvider(
                config, dataSourceRegistry, new SimpleMeterRegistry());
        cacheManager = cacheProviderFactory.create();
    }

    @AfterEach
    void afterEach() throws Exception {
        if (cacheManager != null) {
            cacheManager.close();
        }

        try (final Connection connection = dataSource.getConnection();
             final Statement statement = connection.createStatement()) {
            statement.execute("TRUNCATE TABLE \"CACHE_ENTRY\"");
        }
    }

    @AfterAll
    static void afterAll() {
        if (dataSourceRegistry != null) {
            dataSourceRegistry.closeAll();
        }
    }

    @Test
    void getShouldReturnValueFromLoader() {
        final Cache cache = cacheManager.getCache("test");

        final byte[] result = cache.get("key", k -> "value".getBytes());

        assertThat(result).asString().isEqualTo("value");
    }

    @Test
    void getShouldReturnCachedValueWithoutCallingLoader() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key", "cachedValue".getBytes());
        final var loaderCallCount = new AtomicInteger(0);

        final byte[] result = cache.get("key", k -> {
            loaderCallCount.incrementAndGet();
            return "loaderValue".getBytes();
        });

        assertThat(result).asString().isEqualTo("cachedValue");
        assertThat(loaderCallCount).hasValue(0);
    }

    @Test
    void getShouldReturnNullWhenLoaderReturnsNull() {
        final Cache cache = cacheManager.getCache("test");

        final byte[] result = cache.get("key", k -> null);

        assertThat(result).isNull();
    }

    @Test
    void getShouldPassKeyToLoader() {
        final Cache cache = cacheManager.getCache("test");

        final byte[] result = cache.get("testKey", k -> ("loaded:" + k).getBytes());

        assertThat(result).asString().isEqualTo("loaded:testKey");
    }

    @Test
    void putShouldStoreValue() {
        final Cache cache = cacheManager.getCache("test");

        cache.put("key", "value".getBytes());

        assertThat(cache.get("key", k -> "other".getBytes())).asString().isEqualTo("value");
    }

    @Test
    void putShouldOverwriteExistingValue() {
        final Cache cache = cacheManager.getCache("test");

        cache.put("key", "first".getBytes());
        cache.put("key", "second".getBytes());

        assertThat(cache.get("key", k -> "other".getBytes())).asString().isEqualTo("second");
    }

    @Test
    void getManyShouldReturnCachedEntries() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key1", "value1".getBytes());
        cache.put("key2", "value2".getBytes());

        final Map<String, byte[]> result = cache.getMany(Set.of("key1", "key2"));

        assertThat(result).hasSize(2);
        assertThat(result.get("key1")).asString().isEqualTo("value1");
        assertThat(result.get("key2")).asString().isEqualTo("value2");
    }

    @Test
    void getManyShouldReturnOnlyCachedKeys() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key1", "value1".getBytes());

        final Map<String, byte[]> result = cache.getMany(Set.of("key1", "missing"));

        assertThat(result).hasSize(1);
        assertThat(result.get("key1")).asString().isEqualTo("value1");
        assertThat(result).doesNotContainKey("missing");
    }

    @Test
    void getManyShouldReturnEmptyMapForEmptyKeys() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key1", "value1".getBytes());

        final Map<String, byte[]> result = cache.getMany(Set.of());

        assertThat(result).isEmpty();
    }

    @Test
    void putManyShouldStoreMultipleEntries() {
        final Cache cache = cacheManager.getCache("test");

        cache.putMany(Map.of(
                "key1", "value1".getBytes(),
                "key2", "value2".getBytes(),
                "key3", "value3".getBytes()));

        final Map<String, byte[]> result = cache.getMany(Set.of("key1", "key2", "key3"));
        assertThat(result).hasSize(3);
        assertThat(result.get("key1")).asString().isEqualTo("value1");
        assertThat(result.get("key2")).asString().isEqualTo("value2");
        assertThat(result.get("key3")).asString().isEqualTo("value3");
    }

    @Test
    void putManyShouldOverwriteExistingEntries() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key1", "old1".getBytes());
        cache.put("key2", "old2".getBytes());

        cache.putMany(Map.of(
                "key1", "new1".getBytes(),
                "key2", "new2".getBytes()));

        final Map<String, byte[]> result = cache.getMany(Set.of("key1", "key2"));
        assertThat(result.get("key1")).asString().isEqualTo("new1");
        assertThat(result.get("key2")).asString().isEqualTo("new2");
    }

    @Test
    void putManyShouldHandleEmptyMap() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key", "value".getBytes());

        cache.putMany(Map.of());

        assertThat(cache.get("key", k -> "other".getBytes())).asString().isEqualTo("value");
    }

    @Test
    void invalidateManyShouldRemoveSpecifiedKeys() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key1", "value1".getBytes());
        cache.put("key2", "value2".getBytes());
        cache.put("key3", "value3".getBytes());

        cache.invalidateMany(Set.of("key1", "key2"));

        assertThat(cache.get("key1", k -> "new1".getBytes())).asString().isEqualTo("new1");
        assertThat(cache.get("key2", k -> "new2".getBytes())).asString().isEqualTo("new2");
        assertThat(cache.get("key3", k -> "new3".getBytes())).asString().isEqualTo("value3");
    }

    @Test
    void invalidateManyShouldHandleEmptyCollection() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key", "value".getBytes());

        cache.invalidateMany(Set.of());

        assertThat(cache.get("key", k -> "other".getBytes())).asString().isEqualTo("value");
    }

    @Test
    void invalidateManyShouldHandleNonExistentKeys() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key", "value".getBytes());

        cache.invalidateMany(Set.of("nonExistent"));

        assertThat(cache.get("key", k -> "other".getBytes())).asString().isEqualTo("value");
    }


    @Test
    void invalidateAllShouldRemoveAllEntries() {
        final Cache cache = cacheManager.getCache("test");
        cache.put("key1", "value1".getBytes());
        cache.put("key2", "value2".getBytes());
        cache.put("key3", "value3".getBytes());

        cache.invalidateAll();

        assertThat(cache.get("key1", k -> "new1".getBytes())).asString().isEqualTo("new1");
        assertThat(cache.get("key2", k -> "new2".getBytes())).asString().isEqualTo("new2");
        assertThat(cache.get("key3", k -> "new3".getBytes())).asString().isEqualTo("new3");
    }

    @Test
    void invalidateAllShouldHandleEmptyCache() {
        final Cache cache = cacheManager.getCache("test");

        cache.invalidateAll();

        assertThat(cache.get("key", k -> "value".getBytes())).asString().isEqualTo("value");
    }

}