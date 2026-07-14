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
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.binder.cache.CacheMeterBinder;
import org.jspecify.annotations.Nullable;

import java.util.Optional;

/**
 * @since 5.0.0
 */
final class DatabaseCacheMeterBinder extends CacheMeterBinder<DatabaseCache> {

    DatabaseCacheMeterBinder(DatabaseCache cache, String cacheName) {
        super(cache, cacheName, Tags.empty());
    }

    @Override
    protected @Nullable Long size() {
        final DatabaseCache cache = getCache();
        return cache != null ? cache.size() : null;
    }

    @Override
    protected long hitCount() {
        return Optional
                .ofNullable(getCache())
                .map(DatabaseCache::hitCount)
                .orElse(0L);
    }

    @Override
    protected Long missCount() {
        return Optional
                .ofNullable(getCache())
                .map(DatabaseCache::missCount)
                .orElse(0L);
    }

    @Override
    protected Long evictionCount() {
        return Optional
                .ofNullable(getCache())
                .map(DatabaseCache::evictionCount)
                .orElse(0L);
    }

    @Override
    protected long putCount() {
        return Optional
                .ofNullable(getCache())
                .map(DatabaseCache::putCount)
                .orElse(0L);
    }

    @Override
    protected void bindImplementationSpecificMetrics(MeterRegistry registry) {
    }

}
