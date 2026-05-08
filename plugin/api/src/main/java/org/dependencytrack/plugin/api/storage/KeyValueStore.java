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
package org.dependencytrack.plugin.api.storage;

import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * A key-value store for extensions.
 * <p>
 * Extensions that need to maintain state can use this store for persistence.
 * <p>
 * A store instance is scoped to a single extension.
 * Access to other extensions' values is not possible.
 * <p>
 * Entries in the store are versioned, enabling optimistic concurrency control
 * via {@link #compareAndPut(String, String, Long)} and {@link #compareAndDelete(String, long)}.
 * <p>
 * Performing write operations (puts, deletes) in high frequency should be
 * avoided if possible to reduce I/O overhead. Bulk operations ({@link #putMany(Map)},
 * {@link #getMany(Collection)}, {@link #deleteMany(Collection)}) should be
 * preferred over their singular counterparts, as they are more efficient.
 * They are however not concurrency-safe.
 *
 * @since 5.0.0
 */
public interface KeyValueStore {

    /**
     * An entry in the store.
     *
     * @param key       Key of the entry.
     * @param value     Value of the entry.
     * @param createdAt When the entry was created.
     * @param updatedAt When the entry was updated.
     * @param version   Version of the entry.
     */
    record Entry(
            String key,
            String value,
            Instant createdAt,
            @Nullable Instant updatedAt,
            long version) {

        public Entry {
            requireNonNull(key, "key must not be null");
            requireNonNull(value, "value must not be null");
            requireNonNull(createdAt, "createdAt must not be null");
            if (version < 0) {
                throw new IllegalArgumentException("version must not be negative");
            }
        }

    }

    /**
     * Atomically put multiple key-value pairs in the store.
     *
     * @param kvPairs Key-value pairs to put in the store.
     */
    void putMany(Map<String, String> kvPairs);

    /**
     * Put a single value in the store.
     *
     * @param key   Key of the value.
     * @param value Value to put in the store.
     * @see #putMany(Map)
     */
    default void put(final String key, final String value) {
        requireNonNull(key, "key must not be null");
        requireNonNull(value, "value must not be null");
        putMany(Collections.singletonMap(key, value));
    }

    /**
     * Atomically create or update an entry by comparing its version.
     *
     * @param key             Key of the entry.
     * @param value           Value of the entry.
     * @param expectedVersion Expected version of the existing entry.
     *                        Use {@code null} to create a new entry.
     * @return Result of the operation.
     */
    CompareAndPutResult compareAndPut(String key, String value, @Nullable Long expectedVersion);

    /**
     * Get all entries from the store.
     *
     * @return Zero or more entries.
     */
    List<Entry> getAll();

    /**
     * Get multiple entries from the store.
     *
     * @param keys Keys of entries to get.
     * @return Zero or more entries with matching {@code keys}.
     */
    Map<String, Entry> getMany(Collection<String> keys);

    /**
     * Get a single entry from the store.
     *
     * @param key Key of the entry to get.
     * @return The entry.
     * @see #getMany(Collection)
     */
    default @Nullable Entry get(final String key) {
        requireNonNull(key, "key must not be null");
        return getMany(List.of(key)).get(key);
    }

    /**
     * Atomically delete multiple entries from the store.
     *
     * @param keys Keys of the entries to delete.
     */
    void deleteMany(Collection<String> keys);

    /**
     * Delete a single entry from the store.
     *
     * @param key Key of the entry to delete.
     * @see #deleteMany(Collection)
     */
    default void delete(final String key) {
        requireNonNull(key, "key must not be null");
        deleteMany(List.of(key));
    }

    /**
     * Atomically delete an entry by comparing its version.
     *
     * @param key             Key of the entry.
     * @param expectedVersion Expected version of the existing entry.
     * @return Result of the operation.
     */
    CompareAndDeleteResult compareAndDelete(String key, long expectedVersion);

}
