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
package org.dependencytrack.support.config.source.memory;

import org.eclipse.microprofile.config.spi.ConfigSource;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An in-memory {@link ConfigSource}.
 *
 * @since 5.0.0
 */
public final class MemoryConfigSource implements ConfigSource {

    private static final Map<String, String> PROPERTIES = new ConcurrentHashMap<>();

    public static void setProperties(final Map<String, String> properties) {
        PROPERTIES.putAll(properties);
    }

    public static void setProperty(final String key, final String value) {
        PROPERTIES.put(key, value);
    }

    public static void clear() {
        PROPERTIES.clear();
    }

    @Override
    public int getOrdinal() {
        return Integer.MAX_VALUE;
    }

    @Override
    public Set<String> getPropertyNames() {
        return PROPERTIES.keySet();
    }

    @Override
    public String getValue(final String propertyName) {
        return PROPERTIES.get(propertyName);
    }

    @Override
    public String getName() {
        return MemoryConfigSource.class.getSimpleName();
    }

}
