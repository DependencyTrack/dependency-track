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

import io.smallrye.config.SmallRyeConfigBuilder;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class TaskSchedulerInitializerTest extends PersistenceCapableTest {

    @Test
    void shouldScheduleTasks() {
        final Config config = ConfigProvider.getConfig();
        final var scheduler = new TaskScheduler();
        final var dexEngineMock = mock(DexEngine.class);
        final var pluginManagerMock = mock(PluginManager.class);

        final var servletContextMock = mock(ServletContext.class);
        doReturn(dexEngineMock)
                .when(servletContextMock).getAttribute(eq(DexEngine.class.getName()));
        doReturn(pluginManagerMock)
                .when(servletContextMock).getAttribute(eq(PluginManager.class.getName()));

        final var initializer = new TaskSchedulerInitializer(config, scheduler);
        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        assertThat(scheduler.scheduledTaskIds()).containsExactlyInAnyOrder(
                "Defect Dojo Upload",
                "EPSS Mirror",
                "Expired Session Cleanup",
                "Fortify SSC Upload",
                "GitHub Advisories Mirror",
                "Internal Component Identification",
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

        assertThat(scheduler.isRunning()).isTrue();

        initializer.contextDestroyed(null);

        assertThat(scheduler.isRunning()).isFalse();
    }

    @Test
    void shouldNotStartSchedulerWhenDisabled() {
        final var config = new SmallRyeConfigBuilder()
                .withDefaultValue("dt.task-scheduler.enabled", "false")
                .build();
        final var schedulerMock = mock(TaskScheduler.class);
        final var dexEngineMock = mock(DexEngine.class);
        final var pluginManagerMock = mock(PluginManager.class);

        final var servletContextMock = mock(ServletContext.class);
        doReturn(dexEngineMock)
                .when(servletContextMock).getAttribute(eq(DexEngine.class.getName()));
        doReturn(pluginManagerMock)
                .when(servletContextMock).getAttribute(eq(PluginManager.class.getName()));

        final var initializer = new TaskSchedulerInitializer(config, schedulerMock);
        initializer.contextInitialized(new ServletContextEvent(servletContextMock));

        verify(schedulerMock, never()).start();
    }

}
