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

import org.eclipse.microprofile.health.HealthCheckResponse;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class InitTasksHealthCheckTest {

    @Test
    void shouldReportDownByDefault() {
        final var healthCheck = new InitTasksHealthCheck();
        final HealthCheckResponse response = healthCheck.call();

        assertThat(response.getName()).isEqualTo("init-tasks");
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
        assertThat(response.getData()).isNotPresent();
    }

    @Test
    void shouldReportUpAfterMarkInitialized() {
        final var healthCheck = new InitTasksHealthCheck();
        healthCheck.markInitialized();
        final HealthCheckResponse response = healthCheck.call();

        assertThat(response.getName()).isEqualTo("init-tasks");
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
    }

    @Test
    void shouldTrackCompletedTasks() {
        final var healthCheck = new InitTasksHealthCheck();
        healthCheck.onTaskCompleted("db-migration");
        healthCheck.onTaskCompleted("seeding");

        final HealthCheckResponse response = healthCheck.call();
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
        assertThat(response.getData()).isPresent();
        assertThat(response.getData().get()).containsAllEntriesOf(Map.of(
                "db-migration", "COMPLETED",
                "seeding", "COMPLETED"));
    }

    @Test
    void shouldTrackFailedTask() {
        final var healthCheck = new InitTasksHealthCheck();
        healthCheck.onTaskCompleted("db-migration");
        healthCheck.onTaskFailed("seeding");

        final HealthCheckResponse response = healthCheck.call();
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
        assertThat(response.getData()).isPresent();
        assertThat(response.getData().get()).containsAllEntriesOf(Map.of(
                "db-migration", "COMPLETED",
                "seeding", "FAILED"));
    }

}
