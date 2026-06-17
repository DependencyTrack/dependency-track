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

import org.eclipse.microprofile.health.HealthCheck;

import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;
import java.util.concurrent.CopyOnWriteArrayList;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class HealthCheckRegistry {

    private final List<HealthCheck> checks;

    public HealthCheckRegistry(List<HealthCheck> checks) {
        this.checks = new CopyOnWriteArrayList<>(checks);
    }

    public HealthCheckRegistry() {
        this(Collections.emptyList());
    }

    public List<HealthCheck> getChecks() {
        return List.copyOf(checks);
    }

    public void addCheck(HealthCheck healthCheck) {
        requireNonNull(healthCheck, "healthCheck must not be null");
        checks.add(healthCheck);
    }

    public void discoverChecks() {
        ServiceLoader.load(HealthCheck.class).stream()
                .map(ServiceLoader.Provider::get)
                .forEach(this::addCheck);
    }

}
