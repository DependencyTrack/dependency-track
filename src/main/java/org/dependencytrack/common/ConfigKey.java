package org.dependencytrack.common;

import alpine.Config;

public enum ConfigKey implements Config.Key{
    SNYK_THREAD_BATCH_SIZE("snyk.thread.batch.size", 10),
    SNYK_LIMIT_FOR_PERIOD("snyk.limit.for.period", 1100),
    SNYK_THREAD_TIMEOUT_DURATION("snyk.thread.timeout.duration", 60),
    SNYK_LIMIT_REFRESH_PERIOD("snyk.limit.refresh.period", 60);

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