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
package org.dependencytrack.util;

import alpine.Config;
import alpine.common.metrics.Metrics;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import org.dependencytrack.model.Project;

import java.time.Duration;
import java.util.Collections;
import java.util.concurrent.locks.ReentrantLock;

import static alpine.Config.AlpineKey.METRICS_ENABLED;
import static java.util.Objects.requireNonNull;

/**
 * @since 4.13.0
 */
public final class LockUtil {

    private static final LoadingCache<String, ReentrantLock> CACHE = buildCache();

    private LockUtil() {
    }

    public static ReentrantLock getLockForName(final String name) {
        requireNonNull(name, "name must not be null");
        return CACHE.get(name);
    }

    public static ReentrantLock getLockForProjectAndNamespace(final Project project, final String namespace) {
        requireNonNull(namespace, "namespace must not be null");
        requireNonNull(project, "project must not be null");
        requireNonNull(project.getUuid(), "project UUID must not be null");
        return getLockForName(namespace + ":" + project.getUuid());
    }

    private static LoadingCache<String, ReentrantLock> buildCache() {
        final boolean metricsEnabled = Config.getInstance()
                .getPropertyAsBoolean(METRICS_ENABLED);

        final Caffeine<Object, Object> cacheBuilder = Caffeine.newBuilder()
                .expireAfterAccess(Duration.ofMinutes(1));
        if (metricsEnabled) {
            cacheBuilder.recordStats();
        }

        final LoadingCache<String, ReentrantLock> cache = cacheBuilder
                .build(key -> new ReentrantLock());

        if (metricsEnabled) {
            new CaffeineCacheMetrics<>(cache, "dtrack_locks", Collections.emptyList())
                    .bindTo(Metrics.getRegistry());
        }

        return cache;
    }

}
