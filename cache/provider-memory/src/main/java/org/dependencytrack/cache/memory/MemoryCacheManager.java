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

import com.github.benmanes.caffeine.cache.Caffeine;
import org.dependencytrack.cache.api.Cache;
import org.dependencytrack.cache.api.CacheConfig;
import org.dependencytrack.cache.api.CacheManager;
import org.eclipse.microprofile.config.Config;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.dependencytrack.cache.api.CacheManager.requireValidName;

/**
 * @since 5.0.0
 */
final class MemoryCacheManager implements CacheManager {

    private final Config config;
    private final Map<String, Cache> cacheByName;

    MemoryCacheManager(Config config) {
        this.config = config;
        this.cacheByName = new ConcurrentHashMap<>();
    }

    @Override
    public Cache getCache(String name) {
        requireValidName(name);
        return cacheByName.computeIfAbsent(name, this::createCache);
    }

    @Override
    public void close() {
        for (final Cache cache : cacheByName.values()) {
            cache.invalidateAll();
        }

        cacheByName.clear();
    }

    private Cache createCache(String name) {
        final var cacheConfig = new CacheConfig(config, name);

        final com.github.benmanes.caffeine.cache.Cache<String, Optional<byte[]>> caffeineCache =
                Caffeine.newBuilder()
                        .expireAfterWrite(cacheConfig.ttl())
                        .build();

        return new MemoryCache(caffeineCache);
    }

}
