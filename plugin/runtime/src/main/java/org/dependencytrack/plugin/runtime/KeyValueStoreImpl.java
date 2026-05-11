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
package org.dependencytrack.plugin.runtime;

import org.dependencytrack.plugin.api.storage.CompareAndDeleteResult;
import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.jdbi.v3.core.statement.Query;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class KeyValueStoreImpl implements KeyValueStore {

    private final Jdbi jdbi;
    private final String extensionPointName;
    private final String extensionName;

    KeyValueStoreImpl(
            Jdbi jdbi,
            String extensionPointName,
            String extensionName) {
        this.jdbi = requireNonNull(jdbi, "jdbi must not be null");
        this.extensionPointName = requireNonNull(extensionPointName, "extensionPointName must not be null");
        this.extensionName = requireNonNull(extensionName, "extensionName must not be null");

    }

    @Override
    public void putMany(Map<String, String> kvPairs) {
        requireNonNull(kvPairs, "kvPairs must not be null");
        if (kvPairs.isEmpty()) {
            return;
        }

        jdbi.useTransaction(handle -> {
            final PreparedBatch preparedBatch = handle.prepareBatch("""
                    INSERT INTO "EXTENSION_KV_STORE" ("EXTENSION_POINT", "EXTENSION", "KEY", "VALUE", "CREATED_AT", "VERSION")
                    VALUES (:extensionPointName, :extensionName, :key, :value, NOW(), 0)
                    ON CONFLICT ("EXTENSION_POINT", "EXTENSION", "KEY")
                    DO UPDATE
                    SET "VALUE" = EXCLUDED."VALUE"
                      , "UPDATED_AT" = NOW()
                      , "VERSION" = "EXTENSION_KV_STORE"."VERSION" + 1
                    WHERE "EXTENSION_KV_STORE"."VALUE" IS DISTINCT FROM EXCLUDED."VALUE"
                    """);

            for (final Map.Entry<String, String> entry : kvPairs.entrySet()) {
                preparedBatch
                        .define("queryName", "%s#putMany".formatted(getClass().getSimpleName()))
                        .bind("extensionPointName", extensionPointName)
                        .bind("extensionName", extensionName)
                        .bind("key", entry.getKey())
                        .bind("value", entry.getValue())
                        .add();
            }

            preparedBatch.execute();
        });
    }

    @Override
    public CompareAndPutResult compareAndPut(
            String key,
            String value,
            @Nullable Long expectedVersion) {
        if (expectedVersion == null) {
            return compareAndPutCreate(key, value);
        }

        return compareAndPutUpdate(key, value, expectedVersion);
    }

    private CompareAndPutResult compareAndPutCreate(String key, String value) {
        final Long newVersion = jdbi.inTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    INSERT INTO "EXTENSION_KV_STORE" ("EXTENSION_POINT", "EXTENSION", "KEY", "VALUE", "CREATED_AT", "VERSION")
                    VALUES (:extensionPointName, :extensionName, :key, :value, NOW(), 0)
                    ON CONFLICT ("EXTENSION_POINT", "EXTENSION", "KEY") DO NOTHING
                    RETURNING "VERSION"
                    """);

            return update
                    .define("queryName", "%s#compareAndPutCreate".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bind("key", key)
                    .bind("value", value)
                    .executeAndReturnGeneratedKeys()
                    .mapTo(long.class)
                    .findOne()
                    .orElse(null);
        });

        return newVersion != null
                ? new CompareAndPutResult.Success(newVersion)
                : new CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason.ALREADY_EXISTS);
    }

    private CompareAndPutResult compareAndPutUpdate(
            String key,
            String value,
            long expectedVersion) {
        final Long newVersion = jdbi.inTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    UPDATE "EXTENSION_KV_STORE"
                       SET "VALUE" = :value
                         , "UPDATED_AT" = NOW()
                         , "VERSION" = "VERSION" + 1
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                       AND "KEY" = :key
                       AND "VERSION" = :expectedVersion
                    RETURNING "VERSION"
                    """);

            return update
                    .define("queryName", "%s#compareAndPutUpdate".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bind("key", key)
                    .bind("value", value)
                    .bind("expectedVersion", expectedVersion)
                    .executeAndReturnGeneratedKeys()
                    .mapTo(long.class)
                    .findOne()
                    .orElse(null);
        });

        return newVersion != null
                ? new CompareAndPutResult.Success(newVersion)
                : new CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason.VERSION_MISMATCH);
    }

    @Override
    public List<Entry> getAll() {
        return jdbi.withHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "KEY"
                         , "VALUE"
                         , "CREATED_AT"
                         , "UPDATED_AT"
                         , "VERSION"
                      FROM "EXTENSION_KV_STORE"
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                    """);

            return query
                    .define("queryName", "%s#getAll".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .map(ConstructorMapper.of(Entry.class))
                    .list();
        });
    }

    @Override
    public Map<String, Entry> getMany(Collection<String> keys) {
        requireNonNull(keys, "keys must not be null");
        if (keys.isEmpty()) {
            return Collections.emptyMap();
        }

        return jdbi.withHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "KEY"
                         , "VALUE"
                         , "CREATED_AT"
                         , "UPDATED_AT"
                         , "VERSION"
                      FROM "EXTENSION_KV_STORE"
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                       AND "KEY" = ANY(:keys)
                    """);

            return query
                    .define("queryName", "%s#getMany".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bindArray("keys", String.class, keys)
                    .map(ConstructorMapper.of(Entry.class))
                    .collectToMap(Entry::key, Function.identity());
        });
    }

    @Override
    public void deleteMany(Collection<String> keys) {
        requireNonNull(keys, "keys must not be null");
        if (keys.isEmpty()) {
            return;
        }

        jdbi.useTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    DELETE FROM "EXTENSION_KV_STORE"
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                       AND "KEY" = ANY(:keys)
                    """);

            update
                    .define("queryName", "%s#deleteMany".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bindArray("keys", String.class, keys)
                    .execute();
        });
    }

    @Override
    public CompareAndDeleteResult compareAndDelete(
            String key,
            long expectedVersion) {
        requireNonNull(key, "key must not be null");

        final int modifiedRows = jdbi.inTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    DELETE
                      FROM "EXTENSION_KV_STORE"
                     WHERE "EXTENSION_POINT" = :extensionPointName
                       AND "EXTENSION" = :extensionName
                       AND "KEY" = :key
                       AND "VERSION" = :expectedVersion
                    """);

            return update
                    .define("queryName", "%s#compareAndDelete".formatted(getClass().getSimpleName()))
                    .bind("extensionPointName", extensionPointName)
                    .bind("extensionName", extensionName)
                    .bind("key", key)
                    .bind("expectedVersion", expectedVersion)
                    .execute();
        });

        return modifiedRows > 0
                ? new CompareAndDeleteResult.Success()
                : new CompareAndDeleteResult.Failure(CompareAndDeleteResult.Failure.Reason.VERSION_MISMATCH);
    }

}
