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
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TaskSchedulerHealthCheckTest {

    @Test
    void shouldReportUpWhenSchedulerIsStarted() {
        final HealthCheckResponse response = healthCheckFor(/* started */ true, /* shuttingDown */ false).call();

        assertThat(response.getName()).isEqualTo("task-scheduler");
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
    }

    @Test
    void shouldReportDownWhenSchedulerIsNotStarted() {
        final HealthCheckResponse response = healthCheckFor(/* started */ false, /* shuttingDown */ false).call();

        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
    }

    @Test
    void shouldReportDownWhenSchedulerIsShuttingDown() {
        final HealthCheckResponse response = healthCheckFor(/* started */ true, /* shuttingDown */ true).call();

        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
    }

    private static TaskSchedulerHealthCheck healthCheckFor(boolean started, boolean shuttingDown) {
        final var state = mock(SchedulerState.class);
        when(state.isStarted()).thenReturn(started);
        when(state.isShuttingDown()).thenReturn(shuttingDown);

        final var scheduler = mock(Scheduler.class);
        when(scheduler.getSchedulerState()).thenReturn(state);

        return new TaskSchedulerHealthCheck(scheduler);
    }

}
