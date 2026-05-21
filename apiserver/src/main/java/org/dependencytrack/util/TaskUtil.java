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
package org.dependencytrack.util;

import com.github.kagkarlsson.scheduler.task.schedule.CronSchedule;
import com.github.kagkarlsson.scheduler.task.schedule.CronStyle;
import com.github.kagkarlsson.scheduler.task.schedule.Schedule;
import com.google.common.base.CaseFormat;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import java.time.ZoneOffset;
import java.util.NoSuchElementException;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public final class TaskUtil {

    private static final String PROPERTY_CRON = "cron";

    private TaskUtil() {
    }

    public static Schedule getCronScheduleForTask(final Class<?> taskClass) {
        final String taskName = getTaskConfigName(taskClass);

        final String cronExpression = ConfigProvider.getConfig()
                .getOptionalValue(taskPropertyName(taskName, PROPERTY_CRON), String.class)
                .orElseThrow(() -> new NoSuchElementException("No cron expression configured for task %s".formatted(taskName)));

        return cronSchedule(cronExpression);
    }

    public static Schedule getCronScheduleFromConfig(final Config config, final String configName) {
        return cronSchedule(config.getValue(configName, String.class));
    }

    private static Schedule cronSchedule(final String cronExpression) {
        try {
            return new CronSchedule(cronExpression, ZoneOffset.UTC, CronStyle.UNIX);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Invalid cron expression: %s".formatted(cronExpression), e);
        }
    }

    private static String getTaskConfigName(final Class<?> taskClass) {
        requireNonNull(taskClass);

        return CaseFormat.UPPER_CAMEL.to(CaseFormat.LOWER_UNDERSCORE, taskClass.getSimpleName())
                .replaceAll("_", ".")
                .replaceAll("\\.task$", "");
    }

    private static String taskPropertyName(final String taskName, final String property) {
        return "dt.task.%s.%s".formatted(taskName, property);
    }

}
