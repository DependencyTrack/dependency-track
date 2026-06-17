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

import com.github.kagkarlsson.scheduler.task.helper.RecurringTask;
import com.github.kagkarlsson.scheduler.task.schedule.Schedule;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.common.health.HealthCheckRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.tasks.TaskSchedulerInitializer.TriggerOnFirstRunSchedule;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class TaskSchedulerInitializerTest {

    @Test
    void shouldRegisterAllRecurringTasks() {
        final List<RecurringTask<Void>> tasks =
                TaskSchedulerInitializer.recurringTasks(
                        ConfigProvider.getConfig(),
                        mock(DexEngine.class),
                        mock(PluginManager.class),
                        mock(SecretManager.class));

        assertThat(tasks).extracting(RecurringTask::getName).containsExactlyInAnyOrder(
                "Defect Dojo Upload",
                "EPSS Mirror",
                "Expired Session Cleanup",
                "Fortify SSC Upload",
                "GitHub Advisories Mirror",
                "Kenna Security Upload",
                "Metrics Maintenance",
                "NVD Mirror",
                "OSV Mirror",
                "Package Metadata Maintenance",
                "Package Metadata Resolution",
                "Portfolio Metrics Update",
                "Portfolio Vulnerability Analysis",
                "Project Maintenance",
                "Scheduled Notification Dispatch",
                "Tag Maintenance",
                "Telemetry Submission",
                "Vulnerability Database Maintenance",
                "Vulnerability Metrics Update",
                "Vulnerability Policy Bundle Sync");
    }

    @Test
    void shouldNotStartSchedulerWhenDisabled() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.task-scheduler.enabled", "false")
                .build();
        final var initializer = new TaskSchedulerInitializer(
                config, mock(DataSource.class), new SimpleMeterRegistry(), new HealthCheckRegistry());

        initializer.contextInitialized(new ServletContextEvent(mock(ServletContext.class)));

        assertThat(initializer.scheduler()).isNull();
    }

    @Test
    void shouldJitterInitialExecutionOfTriggerOnFirstRunSchedule() {
        final var schedule = new TriggerOnFirstRunSchedule(mock(Schedule.class));

        final Instant now = Instant.now();
        final Set<Instant> initialExecutionTimes = new HashSet<>();

        for (int i = 0; i < 100; i++) {
            final Instant initialExecutionTime = schedule.getInitialExecutionTime(now);
            assertThat(initialExecutionTime)
                    .isAfterOrEqualTo(now)
                    .isBefore(now.plus(Duration.ofMinutes(1)));
            initialExecutionTimes.add(initialExecutionTime);
        }

        assertThat(initialExecutionTimes).hasSizeGreaterThan(1);
    }

}
