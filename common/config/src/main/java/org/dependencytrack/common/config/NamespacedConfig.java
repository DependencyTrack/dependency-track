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
package org.dependencytrack.common.config;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigValue;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.eclipse.microprofile.config.spi.Converter;

import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class NamespacedConfig implements Config {

    private final Config delegate;
    private final String prefix;

    public NamespacedConfig(Config delegate, String namespace) {
        this.delegate = requireNonNull(delegate, "delegate must not be null");
        this.prefix = requireNonNull(namespace, "namespace must not be null").endsWith(".") ? namespace : namespace + ".";
    }

    @Override
    public <T> T getValue(String propertyName, Class<T> propertyType) {
        return delegate.getValue(prefix + propertyName, propertyType);
    }

    @Override
    public ConfigValue getConfigValue(String propertyName) {
        return delegate.getConfigValue(prefix + propertyName);
    }

    @Override
    public <T> Optional<T> getOptionalValue(String propertyName, Class<T> propertyType) {
        return delegate.getOptionalValue(prefix + propertyName, propertyType);
    }

    @Override
    public Iterable<String> getPropertyNames() {
        return StreamSupport.stream(delegate.getPropertyNames().spliterator(), false)
                .filter(name -> name.startsWith(prefix))
                .map(name -> name.substring(prefix.length()))
                .collect(Collectors.toSet());
    }

    @Override
    public Iterable<ConfigSource> getConfigSources() {
        return delegate.getConfigSources();
    }

    @Override
    public <T> Optional<Converter<T>> getConverter(Class<T> forType) {
        return delegate.getConverter(forType);
    }

    @Override
    public <T> T unwrap(Class<T> type) {
        throw new UnsupportedOperationException();
    }

}
