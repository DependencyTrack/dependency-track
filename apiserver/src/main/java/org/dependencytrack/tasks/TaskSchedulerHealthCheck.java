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
package org.dependencytrack.tasks;

import com.github.kagkarlsson.scheduler.Scheduler;
import com.github.kagkarlsson.scheduler.SchedulerState;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
@Liveness
final class TaskSchedulerHealthCheck implements HealthCheck {

    private final Scheduler scheduler;

    TaskSchedulerHealthCheck(Scheduler scheduler) {
        this.scheduler = requireNonNull(scheduler, "scheduler must not be null");
    }

    @Override
    public HealthCheckResponse call() {
        final SchedulerState state = scheduler.getSchedulerState();

        final String stateStr;
        if (state.isStarted()) {
            stateStr = "started";
        } else if (state.isPaused()) {
            stateStr = "paused";
        } else if (state.isShuttingDown()) {
            stateStr = "shutting down";
        } else {
            stateStr = "unknown";
        }

        return HealthCheckResponse
                .named("task-scheduler")
                .status(state.isStarted() && !state.isShuttingDown())
                .withData("state", stateStr)
                .build();
    }

}
