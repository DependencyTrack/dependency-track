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
package org.dependencytrack.plugin.api;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class MutableServiceRegistry implements ServiceRegistry {

    private final Map<Class<?>, Object> services = new HashMap<>();
    private boolean frozen;

    public <T> MutableServiceRegistry register(Class<T> type, T service) {
        if (frozen) {
            throw new IllegalStateException(
                    "Cannot register service after registry is already frozen");
        }
        requireNonNull(type, "type must not be null");
        requireNonNull(service, "service must not be null");
        if (services.containsKey(type)) {
            throw new IllegalStateException(
                    "Service already registered for type: " + type.getName());
        }

        services.put(type, service);
        return this;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> Optional<T> get(Class<T> type) {
        requireNonNull(type, "type must not be null");
        return Optional.ofNullable((T) services.get(type));
    }

    public MutableServiceRegistry freeze() {
        this.frozen = true;
        return this;
    }

}
