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

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.Closeable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @since 5.0.0
 */
final class DatabaseCacheMaintenanceWorker implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseCacheMaintenanceWorker.class);

    private final DataSource dataSource;
    private final Duration initialDelay;
    private final Duration interval;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Map<String, DatabaseCache> cacheByName;
    private @Nullable ScheduledExecutorService executor;

    DatabaseCacheMaintenanceWorker(
            DataSource dataSource,
            Duration initialDelay,
            Duration interval) {
        this.dataSource = dataSource;
        this.initialDelay = initialDelay;
        this.interval = interval;
        this.cacheByName = new ConcurrentHashMap<>();
    }

    void start() {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("Already started");
        }

        executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name(getClass().getSimpleName(), 0)
                        .factory());
        executor.scheduleAtFixedRate(
                () -> {
                    try {
                        performMaintenance();
                    } catch (SQLException | RuntimeException e) {
                        LOGGER.error("Failed to perform cache maintenance", e);
                    }
                },
                initialDelay.toMillis(),
                interval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    void registerCache(DatabaseCache cache) {
        LOGGER.debug("Registering cache '{}'", cache.name());
        cacheByName.putIfAbsent(cache.name(), cache);
    }

    void performMaintenance() throws SQLException {
        LOGGER.debug("Starting cache maintenance");

        try (final Connection connection = dataSource.getConnection()) {
            deleteExpiredEntries(connection);
            refreshCachedSizes(connection);
        }

        LOGGER.debug("Cache maintenance completed");
    }

    private void deleteExpiredEntries(Connection connection) throws SQLException {
        try (final PreparedStatement ps = connection.prepareStatement("""
                WITH cte_expired AS (
                  DELETE
                    FROM "CACHE_ENTRY"
                   WHERE "EXPIRES_AT" < NOW()
                  RETURNING "CACHE_NAME"
                )
                SELECT "CACHE_NAME"
                     , COUNT(*)
                  FROM cte_expired
                 GROUP BY "CACHE_NAME"
                """);
             final ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                final String cacheName = rs.getString(1);
                final int entriesEvicted = rs.getInt(2);
                LOGGER.debug("Deleted {} expired entries for cache '{}'", entriesEvicted, cacheName);

                final DatabaseCache cache = cacheByName.get(cacheName);
                if (cache != null) {
                    cache.onEntriesEvicted(entriesEvicted);
                }
            }
        }
    }

    private void refreshCachedSizes(Connection connection) throws SQLException {
        final Set<String> cachesWithoutEntries = new HashSet<>(cacheByName.keySet());

        try (final PreparedStatement ps = connection.prepareStatement("""
                SELECT "CACHE_NAME"
                     , COUNT(*)
                  FROM "CACHE_ENTRY"
                 WHERE "CACHE_NAME" = ANY(?)
                   AND "EXPIRES_AT" > NOW()
                 GROUP BY "CACHE_NAME"
                """)) {
            ps.setArray(1, connection.createArrayOf("TEXT", cachesWithoutEntries.toArray(String[]::new)));

            try (final ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    final String cacheName = rs.getString(1);
                    final long size = rs.getLong(2);
                    cachesWithoutEntries.remove(cacheName);

                    final DatabaseCache cache = cacheByName.get(cacheName);
                    if (cache != null) {
                        cache.onSizeRefreshed(size);
                    }
                }
            }
        }

        // Zero out caches that have no entries so stale sizes
        // don't linger after full eviction.
        for (final String cacheName : cachesWithoutEntries) {
            final DatabaseCache cache = cacheByName.get(cacheName);
            if (cache != null) {
                cache.onSizeRefreshed(0L);
            }
        }
    }

    @Override
    public void close() {
        if (!running.compareAndSet(true, false)) {
            return;
        }

        if (executor != null) {
            executor.close();
        }
    }

}
