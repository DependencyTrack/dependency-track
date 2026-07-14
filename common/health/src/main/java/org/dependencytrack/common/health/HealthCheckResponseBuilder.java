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
package org.dependencytrack.common.health;

import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponse.Status;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.function.Predicate.not;

/**
 * Implementation of the MicroProfile Health SPI.
 *
 * @see <a href="https://download.eclipse.org/microprofile/microprofile-health-3.1/microprofile-health-spec-3.1.html#_spi_usage">MicroProfile Health SPI Usage</a>
 * @since 5.0.0
 */
final class HealthCheckResponseBuilder extends org.eclipse.microprofile.health.HealthCheckResponseBuilder {

    private @Nullable String name;
    private Status status = Status.DOWN;
    private final Map<String, Object> data = new HashMap<>();

    @Override
    public org.eclipse.microprofile.health.HealthCheckResponseBuilder name(final String name) {
        this.name = name;
        return this;
    }

    @Override
    public org.eclipse.microprofile.health.HealthCheckResponseBuilder withData(final String key, final String value) {
        data.put(key, value);
        return this;
    }

    @Override
    public org.eclipse.microprofile.health.HealthCheckResponseBuilder withData(final String key, final long value) {
        data.put(key, value);
        return this;
    }

    @Override
    public org.eclipse.microprofile.health.HealthCheckResponseBuilder withData(final String key, final boolean value) {
        data.put(key, value);
        return this;
    }

    @Override
    public org.eclipse.microprofile.health.HealthCheckResponseBuilder up() {
        status = Status.UP;
        return this;
    }

    @Override
    public org.eclipse.microprofile.health.HealthCheckResponseBuilder down() {
        status = Status.DOWN;
        return this;
    }

    @Override
    public org.eclipse.microprofile.health.HealthCheckResponseBuilder status(final boolean up) {
        status = up ? Status.UP : Status.DOWN;
        return this;
    }

    @Override
    public HealthCheckResponse build() {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Health check responses must provide a name");
        }

        return new HealthCheckResponse(name, status, Optional.of(data).filter(not(Map::isEmpty)));
    }

}
