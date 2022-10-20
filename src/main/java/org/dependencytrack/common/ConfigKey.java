package org.dependencytrack.common;

import alpine.Config;

public enum ConfigKey implements Config.Key{
    SNYK_THREAD_BATCH_SIZE("snyk.thread.batch.size", 10);

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