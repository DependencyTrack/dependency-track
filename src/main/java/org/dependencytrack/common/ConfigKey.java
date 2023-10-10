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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.common;

import alpine.Config;

import java.time.Duration;

public enum ConfigKey implements Config.Key {

    SNYK_THREAD_POOL_SIZE("snyk.thread.pool.size", 10),
    SNYK_RETRY_MAX_ATTEMPTS("snyk.retry.max.attempts", 10),
    SNYK_RETRY_EXPONENTIAL_BACKOFF_MULTIPLIER("snyk.retry.exponential.backoff.multiplier", 2),
    SNYK_RETRY_EXPONENTIAL_BACKOFF_INITIAL_DURATION_SECONDS("snyk.retry.exponential.backoff.initial.duration.seconds", 1),
    SNYK_RETRY_EXPONENTIAL_BACKOFF_MAX_DURATION_SECONDS("snyk.retry.exponential.backoff.max.duration.seconds", 60),
    OSSINDEX_REQUEST_MAX_PURL("ossindex.request.max.purl", 128),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MAX_ATTEMPTS("ossindex.retry.backoff.max.attempts", 10),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MULTIPLIER("ossindex.retry.backoff.multiplier", 2),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MAX_DURATION("ossindex.retry.backoff.max.duration", Duration.ofMinutes(10).toMillis()),
    REPO_META_ANALYZER_CACHE_STAMPEDE_BLOCKER_ENABLED("repo.meta.analyzer.cacheStampedeBlocker.enabled", true),
    REPO_META_ANALYZER_CACHE_STAMPEDE_BLOCKER_LOCK_BUCKETS("repo.meta.analyzer.cacheStampedeBlocker.lock.buckets", 1000),
    REPO_META_ANALYZER_CACHE_STAMPEDE_BLOCKER_MAX_ATTEMPTS("repo.meta.analyzer.cacheStampedeBlocker.max.attempts", 10),
    SYSTEM_REQUIREMENT_CHECK_ENABLED("system.requirement.check.enabled", true);

    private final String propertyName;
    private final Object defaultValue;

    ConfigKey(final String propertyName, final Object defaultValue) {
        this.propertyName = propertyName;
        this.defaultValue = defaultValue;
    }

    @Override
    public String getPropertyName() {
        return propertyName;
    }

    @Override
    public Object getDefaultValue() {
        return defaultValue;
    }

}
