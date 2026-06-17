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
package org.dependencytrack.capabilities;

import org.glassfish.hk2.api.ServiceLocator;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.TreeMap;

/**
 * @since 5.0.0
 */
public final class SystemCapabilitiesAggregator {

    private static final Logger LOGGER = LoggerFactory.getLogger(SystemCapabilitiesAggregator.class);

    private final Map<String, CapabilityProvider> providerByNamespace;

    public SystemCapabilitiesAggregator(ServiceLocator serviceLocator) {
        this(ServiceLoader.load(CapabilityProvider.class).stream()
                .map(ServiceLoader.Provider::get)
                .toList(), serviceLocator);
    }

    public SystemCapabilitiesAggregator(
            List<CapabilityProvider> providers,
            ServiceLocator serviceLocator) {
        final var byNamespace = new TreeMap<String, CapabilityProvider>();

        for (final CapabilityProvider provider : providers) {
            final String namespace = provider.namespace();
            final CapabilityProvider previous = byNamespace.putIfAbsent(namespace, provider);
            if (previous != null) {
                throw new IllegalStateException(
                        "Duplicate capability namespace '%s' contributed by %s and %s".formatted(
                                namespace,
                                previous.getClass().getName(),
                                provider.getClass().getName()));
            }

            provider.init(serviceLocator);
            LOGGER.debug(
                    "Registered capability provider {} for namespace '{}'",
                    provider.getClass().getName(),
                    namespace);
        }

        this.providerByNamespace = Collections.unmodifiableMap(new LinkedHashMap<>(byNamespace));
    }

    public Map<String, Map<String, Object>> collect() {
        final var result = new LinkedHashMap<String, Map<String, Object>>();

        for (final var entry : providerByNamespace.entrySet()) {
            final String namespace = entry.getKey();
            final CapabilityProvider provider = entry.getValue();
            try {
                final Map<String, Object> capabilities = provider.capabilities();
                requireValidCapabilities(namespace, capabilities);
                if (capabilities == null || capabilities.isEmpty()) {
                    continue;
                }

                result.put(namespace, Collections.unmodifiableMap(new TreeMap<>(capabilities)));
            } catch (RuntimeException e) {
                LOGGER.warn(
                        "Failed to collect capabilities for namespace '{}'; omitting from response",
                        namespace, e);
            }
        }

        return Collections.unmodifiableMap(result);
    }

    private static String requireValidCapabilityKey(String path, @Nullable Object key) {
        if (key instanceof final String s && !s.isEmpty()) {
            return s;
        }

        throw new IllegalStateException(
                "Capability '%s' has invalid key: %s".formatted(path, key));
    }

    private static void requireValidCapabilities(String namespace, @Nullable Map<String, Object> capabilities) {
        if (capabilities == null) {
            return;
        }

        for (final Map.Entry<String, Object> entry : capabilities.entrySet()) {
            final String key = requireValidCapabilityKey(namespace, entry.getKey());
            validateValidCapabilityField(namespace + "." + key, entry.getValue());
        }
    }

    private static void validateValidCapabilityField(String path, @Nullable Object value) {
        if (value == null || value instanceof Boolean || value instanceof Number || value instanceof String) {
            return;
        }

        if (value instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++) {
                validateValidCapabilityField(path + "[" + i + "]", list.get(i));
            }
            return;
        }

        if (value instanceof Map<?, ?> map) {
            for (final Map.Entry<?, ?> entry : map.entrySet()) {
                final String key = requireValidCapabilityKey(path, entry.getKey());
                validateValidCapabilityField(path + "." + key, entry.getValue());
            }
            return;
        }

        throw new IllegalStateException(
                "Capability '%s' has unsupported value type %s".formatted(
                        path, value.getClass().getName()));
    }

}
