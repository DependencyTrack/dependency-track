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

import com.github.kagkarlsson.scheduler.task.ExecutionContext;
import com.github.kagkarlsson.scheduler.task.TaskInstance;
import com.github.kagkarlsson.scheduler.task.helper.RecurringTask;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.pkghealth.PackageHealthSettings;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.secret.management.SecretManager;
import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.ConfigPropertyConstants.PACKAGE_HEALTH_RESOLUTION_ENABLED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class PackageHealthResolutionScheduleTest extends PersistenceCapableTest {

    @Test
    void shouldStartResolutionWhenEnabled() {
        createEnabledProperty("true");

        final DexEngine dexEngine = executePackageHealthTask();

        verify(dexEngine).createRun(any());
    }

    @Test
    void shouldStartResolutionWhenPropertyIsMissing() {
        final DexEngine dexEngine = executePackageHealthTask();

        verify(dexEngine).createRun(any());
        assertThat(withJdbiHandle(PackageHealthSettings::isEnabled)).isTrue();
    }

    @Test
    void shouldNotStartResolutionWhenDisabled() {
        createEnabledProperty("false");

        final DexEngine dexEngine = executePackageHealthTask();

        verify(dexEngine, never()).createRun(any());
        assertThat(withJdbiHandle(PackageHealthSettings::isEnabled)).isFalse();
    }

    private void createEnabledProperty(final String value) {
        qm.createConfigProperty(
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getGroupName(),
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getPropertyName(),
                value,
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getPropertyType(),
                PACKAGE_HEALTH_RESOLUTION_ENABLED.getDescription());
    }

    private DexEngine executePackageHealthTask() {
        final DexEngine dexEngine = mock(DexEngine.class);
        final List<RecurringTask<Void>> tasks = TaskSchedulerInitializer.recurringTasks(
                ConfigProvider.getConfig(), dexEngine, mock(PluginManager.class), mock(SecretManager.class));
        final RecurringTask<Void> task = tasks.stream()
                .filter(candidate -> "Package Health Metadata Resolution".equals(candidate.getName()))
                .findFirst()
                .orElseThrow();

        task.execute(new TaskInstance<>(task.getName(), task.getName()), mock(ExecutionContext.class));
        return dexEngine;
    }
}
