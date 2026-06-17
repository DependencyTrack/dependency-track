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
package org.dependencytrack.cache.memory;

import org.dependencytrack.cache.api.Cache;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * @since 5.0.0
 */
final class MemoryCache implements Cache {

    private final com.github.benmanes.caffeine.cache.Cache<String, Optional<byte[]>> delegate;

    MemoryCache(com.github.benmanes.caffeine.cache.Cache<String, Optional<byte[]>> delegate) {
        this.delegate = delegate;
    }

    @Override
    public byte @Nullable [] get(String key, Function<String, byte @Nullable []> loader) {
        return delegate.get(key, k -> Optional.ofNullable(loader.apply(k))).orElse(null);
    }

    @Override
    public Map<String, byte @Nullable []> getMany(Set<String> keys) {
        final Map<String, Optional<byte[]>> result = delegate.getAllPresent(keys);
        if (result.isEmpty()) {
            return Map.of();
        }

        final var unwrappedResult = new HashMap<String, byte @Nullable []>(result.size());
        for (final var entry : result.entrySet()) {
            unwrappedResult.put(entry.getKey(), entry.getValue().orElse(null));
        }

        return unwrappedResult;
    }

    @Override
    public void put(String key, byte @Nullable [] value) {
        delegate.put(key, Optional.ofNullable(value));
    }

    @Override
    public void putMany(Map<String, byte @Nullable []> entries) {
        if (entries.isEmpty()) {
            return;
        }

        final var entriesWrapped = new HashMap<String, Optional<byte[]>>(entries.size());
        for (final var entry : entries.entrySet()) {
            entriesWrapped.put(entry.getKey(), Optional.ofNullable(entry.getValue()));
        }

        delegate.putAll(entriesWrapped);
    }

    @Override
    public void invalidateMany(Set<String> keys) {
        delegate.invalidateAll(keys);
    }

    @Override
    public void invalidateAll() {
        delegate.invalidateAll();
    }

}
