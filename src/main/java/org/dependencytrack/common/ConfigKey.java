package org.dependencytrack.common;

import alpine.Config;

import java.time.Duration;

public enum ConfigKey implements Config.Key {
    DEFAULT_PROJECT_DISABLE("default.project.disable", false),
    DEFAULT_PROJECT_TAGS("default.project.tags", null),
    SNYK_THREAD_BATCH_SIZE("snyk.thread.batch.size", 10),
    SNYK_LIMIT_FOR_PERIOD("snyk.limit.for.period", 1500),
    SNYK_THREAD_TIMEOUT_DURATION("snyk.thread.timeout.duration", 60),
    SNYK_LIMIT_REFRESH_PERIOD("snyk.limit.refresh.period", 60),
    OSSINDEX_REQUEST_MAX_PURL("ossindex.request.max.purl", 128),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MAX_ATTEMPTS("ossindex.retry.backoff.max.attempts", 10),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MULTIPLIER("ossindex.retry.backoff.multiplier", 2),
    OSSINDEX_RETRY_EXPONENTIAL_BACKOFF_MAX_DURATION("ossindex.retry.backoff.max.duration", Duration.ofMinutes(10).toMillis());

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