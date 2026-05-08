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
package org.dependencytrack.init;

import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Startup;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @since 5.0.0
 */
@Startup
public final class InitTasksHealthCheck implements HealthCheck, InitTaskListener {

    private volatile boolean initialized;
    private final Map<String, String> taskStatuses = new ConcurrentHashMap<>();

    @Override
    public HealthCheckResponse call() {
        final HealthCheckResponseBuilder builder =
                HealthCheckResponse.named("init-tasks")
                        .status(initialized);
        taskStatuses.forEach(builder::withData);
        return builder.build();
    }

    @Override
    public void onTaskStarted(String taskName) {
        taskStatuses.put(taskName, "STARTED");
    }

    @Override
    public void onTaskCompleted(String taskName) {
        taskStatuses.put(taskName, "COMPLETED");
    }

    @Override
    public void onTaskFailed(String taskName) {
        taskStatuses.put(taskName, "FAILED");
    }

    public void markInitialized() {
        initialized = true;
    }

}
