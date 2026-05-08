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

import io.micrometer.core.instrument.MeterRegistry;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.cache.api.CacheConfig;
import org.dependencytrack.cache.api.CacheManager;
import org.eclipse.microprofile.config.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static org.dependencytrack.cache.api.CacheManager.requireValidName;

/**
 * @since 5.0.0
 */
final class DatabaseCacheManager implements CacheManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseCacheManager.class);

    private final Config config;
    private final DataSource dataSource;
    private final MeterRegistry meterRegistry;
    private final ConcurrentMap<String, Cache> caches;
    private final DatabaseCacheMaintenanceWorker maintenanceWorker;

    DatabaseCacheManager(
            Config config,
            DataSource dataSource,
            MeterRegistry meterRegistry,
            DatabaseCacheMaintenanceWorker maintenanceWorker) {
        this.config = config;
        this.dataSource = dataSource;
        this.meterRegistry = meterRegistry;
        this.caches = new ConcurrentHashMap<>();
        this.maintenanceWorker = maintenanceWorker;
    }

    @Override
    public Cache getCache(String name) {
        requireValidName(name);
        return caches.computeIfAbsent(name, this::createCache);
    }

    @Override
    public void close() {
        maintenanceWorker.close();
    }

    private DatabaseCache createCache(String name) {
        LOGGER.debug("Creating cache '{}'", name);

        final var cacheConfig = new CacheConfig(config, name);
        final var cache = new DatabaseCache(name, cacheConfig.ttl(), dataSource);
        maintenanceWorker.registerCache(cache);

        new DatabaseCacheMeterBinder(cache, name)
                .bindTo(meterRegistry);

        return cache;
    }

}
