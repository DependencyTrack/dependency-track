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

import org.dependencytrack.cache.api.Cache;
import org.jspecify.annotations.Nullable;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

/**
 * @since 5.0.0
 */
final class DatabaseCache implements Cache {

    private final String name;
    private final Duration ttl;
    private final DataSource dataSource;
    private final AtomicLong hitCount = new AtomicLong();
    private final AtomicLong missCount = new AtomicLong();
    private final AtomicLong putCount = new AtomicLong();
    private final AtomicLong evictionCount = new AtomicLong();
    private final AtomicLong cachedSize = new AtomicLong(-1L);

    DatabaseCache(
            String name,
            Duration ttl,
            DataSource dataSource) {
        this.name = name;
        this.ttl = ttl;
        this.dataSource = dataSource;
    }

    @Override
    public byte @Nullable [] get(String key, Function<String, byte @Nullable []> loader) {
        // NB: Ideally this whole operation would be wrapped in a transaction-level
        // advisory lock. But loader may be slow and / or perform expensive I/O.
        // We can't risk a DB connection being blocked for this long.

        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT "VALUE"
                       FROM "CACHE_ENTRY"
                      WHERE "CACHE_NAME" = ?
                        AND "KEY" = ?
                        AND "EXPIRES_AT" > NOW()
                     """)) {
            ps.setString(1, this.name);
            ps.setString(2, key);

            final ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                hitCount.incrementAndGet();
                return rs.getBytes(1);
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }

        missCount.incrementAndGet();
        final byte[] value = loader.apply(key);

        put(key, value);

        return value;
    }

    @Override
    public Map<String, byte @Nullable []> getMany(Set<String> keys) {
        final var result = new HashMap<String, byte @Nullable []>();

        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     SELECT "KEY"
                          , "VALUE"
                       FROM "CACHE_ENTRY"
                      WHERE "CACHE_NAME" = ?
                        AND "KEY" = ANY(?)
                        AND "EXPIRES_AT" > NOW()
                     """)) {
            ps.setString(1, this.name);
            ps.setArray(2, connection.createArrayOf("TEXT", keys.toArray(String[]::new)));

            final ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                result.put(rs.getString("KEY"), rs.getBytes("VALUE"));
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }

        hitCount.addAndGet(result.size());
        missCount.addAndGet(keys.size() - result.size());
        return result;
    }

    @Override
    public void put(String key, byte @Nullable [] value) {
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     INSERT INTO "CACHE_ENTRY" ("CACHE_NAME", "KEY", "VALUE", "EXPIRES_AT")
                     VALUES (?, ?, ?, NOW() + (INTERVAL '1 millisecond' * ?))
                     ON CONFLICT ("CACHE_NAME", "KEY") DO UPDATE
                     SET "VALUE" = EXCLUDED."VALUE"
                       , "EXPIRES_AT" = EXCLUDED."EXPIRES_AT"
                     """)) {
            ps.setString(1, this.name);
            ps.setString(2, key);
            ps.setBytes(3, value);
            ps.setLong(4, ttl.toMillis());
            final int entriesModified = ps.executeUpdate();
            putCount.addAndGet(entriesModified);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void putMany(Map<String, byte @Nullable []> entries) {
        final var cacheNames = new String[entries.size()];
        final var keys = new String[entries.size()];
        final var values = new byte[entries.size()][];

        int i = 0;
        for (final var entry : entries.entrySet()) {
            cacheNames[i] = this.name;
            keys[i] = entry.getKey();
            values[i] = entry.getValue();
            i++;
        }

        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     INSERT INTO "CACHE_ENTRY" ("CACHE_NAME", "KEY", "VALUE", "EXPIRES_AT")
                     SELECT cache_name
                          , key
                          , value
                          , NOW() + (INTERVAL '1 millisecond' * ?)
                       FROM UNNEST(?, ?, ?)
                         AS t(cache_name, key, value)
                     ON CONFLICT ("CACHE_NAME", "KEY") DO UPDATE
                     SET "VALUE" = EXCLUDED."VALUE"
                       , "EXPIRES_AT" = EXCLUDED."EXPIRES_AT"
                     """)) {
            ps.setLong(1, ttl.toMillis());
            ps.setArray(2, connection.createArrayOf("TEXT", cacheNames));
            ps.setArray(3, connection.createArrayOf("TEXT", keys));
            ps.setArray(4, connection.createArrayOf("BYTEA", values));
            final int entriesModified = ps.executeUpdate();
            putCount.addAndGet(entriesModified);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void invalidateMany(Set<String> keys) {
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     DELETE
                       FROM "CACHE_ENTRY"
                      WHERE "CACHE_NAME" = ?
                        AND "KEY" = ANY(?)
                     """)) {
            ps.setString(1, name);
            ps.setArray(2, connection.createArrayOf("TEXT", keys.toArray(String[]::new)));
            final int entriesEvicted = ps.executeUpdate();
            evictionCount.addAndGet(entriesEvicted);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void invalidateAll() {
        try (final Connection connection = dataSource.getConnection();
             final PreparedStatement ps = connection.prepareStatement("""
                     DELETE
                       FROM "CACHE_ENTRY"
                      WHERE "CACHE_NAME" = ?
                     """)) {
            ps.setString(1, name);
            final int entriesEvicted = ps.executeUpdate();
            evictionCount.addAndGet(entriesEvicted);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    String name() {
        return name;
    }

    long hitCount() {
        return hitCount.get();
    }

    long missCount() {
        return missCount.get();
    }

    long putCount() {
        return putCount.get();
    }

    long evictionCount() {
        return evictionCount.get();
    }

    void onEntriesEvicted(int count) {
        evictionCount.addAndGet(count);
    }

    void onSizeRefreshed(long size) {
        cachedSize.set(size);
    }

    @Nullable Long size() {
        final long size = cachedSize.get();
        return size < 0 ? null : size;
    }

}
