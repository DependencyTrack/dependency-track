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
package org.dependencytrack.plugin.testing;

import org.dependencytrack.plugin.api.storage.CompareAndDeleteResult;
import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Objects.requireNonNull;

/**
 * An in-memory {@link KeyValueStore}.
 *
 * @since 5.0.0
 */
public final class MockKeyValueStore implements KeyValueStore {

    private final ConcurrentMap<String, Entry> kvMap;

    MockKeyValueStore(final ConcurrentMap<String, Entry> kvMap) {
        this.kvMap = kvMap;
    }

    public MockKeyValueStore() {
        this(new ConcurrentHashMap<>());
    }

    @Override
    public void putMany(final Map<String, String> kvPairs) {
        requireNonNull(kvPairs, "kvPairs must not be null");

        final var now = Instant.now();
        for (final Map.Entry<String, String> kvPairEntry : kvPairs.entrySet()) {
            kvMap.merge(
                    kvPairEntry.getKey(),
                    new Entry(kvPairEntry.getKey(), kvPairEntry.getValue(), now, null, 0),
                    (a, b) -> {
                        if (a == null) {
                            return b;
                        } else if (Objects.equals(a.value(), b.value())) {
                            return a;
                        }

                        return new Entry(
                                a.key(),
                                b.value(),
                                a.createdAt(),
                                b.createdAt(),
                                a.version() + 1);
                    });
        }
    }

    @Override
    public CompareAndPutResult compareAndPut(
            final String key,
            final String value,
            final @Nullable Long expectedVersion) {
        final Instant now = Instant.now();

        if (expectedVersion == null) {
            final Entry existingEntry = kvMap.putIfAbsent(
                    key, new Entry(key, value, now, null, 0));

            return existingEntry == null
                    ? new CompareAndPutResult.Success(0)
                    : new CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason.ALREADY_EXISTS);
        }

        // This flag is necessary to correctly detect whether the version
        // has matched. computeIfPresent returns null when the entry doesn't
        // exist, but non-null values otherwise. Comparing entry values is
        // not sufficient because those might be legitimately equal despite
        // the entry having been modified.
        final var versionMatched = new AtomicBoolean(false);

        final Entry entry = kvMap.computeIfPresent(key, (_, existingEntry) -> {
            if (existingEntry.version() != expectedVersion) {
                return existingEntry;
            }

            versionMatched.set(true);
            return new Entry(
                    key,
                    value,
                    existingEntry.createdAt(),
                    now,
                    existingEntry.version() + 1);
        });
        if (entry == null) {
            return new CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason.VERSION_MISMATCH);
        }

        return versionMatched.get()
                ? new CompareAndPutResult.Success(entry.version())
                : new CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason.VERSION_MISMATCH);
    }

    @Override
    public CompareAndDeleteResult compareAndDelete(final String key, final long expectedVersion) {
        requireNonNull(key, "key must not be null");

        // This flag is necessary to differentiate between cases where the
        // entry doesn't exist, and cases where the entry was successfully deleted.
        // In both scenarios computeIfPresent returns null.
        final var versionMatched = new AtomicBoolean(false);

        kvMap.computeIfPresent(key, (_, entry) -> {
            if (entry.version() == expectedVersion) {
                versionMatched.set(true);
                return null;
            }

            return entry;
        });

        return versionMatched.get()
                ? new CompareAndDeleteResult.Success()
                : new CompareAndDeleteResult.Failure(CompareAndDeleteResult.Failure.Reason.VERSION_MISMATCH);
    }

    @Override
    public List<Entry> getAll() {
        return List.copyOf(kvMap.values());
    }

    @Override
    public Map<String, Entry> getMany(final Collection<String> keys) {
        requireNonNull(keys, "keys must not be null");
        if (keys.isEmpty()) {
            return Collections.emptyMap();
        }

        final var result = new HashMap<String, Entry>(keys.size());
        for (final String key : keys) {
            final Entry entry = kvMap.get(key);
            if (entry != null) {
                result.put(key, entry);
            }
        }

        return result;
    }

    @Override
    public void deleteMany(final Collection<String> keys) {
        requireNonNull(keys, "keys must not be null");
        if (keys.isEmpty()) {
            return;
        }

        keys.forEach(kvMap::remove);
    }

}
