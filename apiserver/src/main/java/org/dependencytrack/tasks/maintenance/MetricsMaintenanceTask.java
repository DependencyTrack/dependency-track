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
package org.dependencytrack.tasks.maintenance;

import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import org.dependencytrack.event.maintenance.MetricsMaintenanceEvent;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.jdbi.v3.core.Handle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static net.javacrumbs.shedlock.core.LockAssert.assertLocked;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_METRICS_RETENTION_DAYS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

/**
 * @since 5.0.0
 */
public class MetricsMaintenanceTask implements Subscriber {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetricsMaintenanceTask.class);

    @Override
    public void inform(final Event event) {
        if (!(event instanceof MetricsMaintenanceEvent)) {
            return;
        }

        final long startTimeNs = System.nanoTime();
        try (final Handle jdbiHandle = openJdbiHandle()) {
            LOGGER.info("Starting metrics maintenance");
            final Statistics statistics = executeWithLock(
                    getLockConfigForTask(MetricsMaintenanceTask.class),
                    () -> informLocked(jdbiHandle));
            if (statistics == null) {
                LOGGER.info("Task is locked by another instance; Skipping");
                return;
            }

            final var taskDuration = Duration.ofNanos(System.nanoTime() - startTimeNs);
            LOGGER.info("Completed in %s: %s".formatted(taskDuration, statistics));
        } catch (Throwable e) {
            final var taskDuration = Duration.ofNanos(System.nanoTime() - startTimeNs);
            LOGGER.error("Failed to complete after %s".formatted(taskDuration), e);
        }
    }

    private record Statistics(
            Duration retentionDuration,
            int deletedComponentMetrics,
            int deletedProjectMetrics) {
    }

    private Statistics informLocked(final Handle jdbiHandle) {
        assertLocked();

        final var configPropertyDao = jdbiHandle.attach(ConfigPropertyDao.class);
        final var metricsDao = jdbiHandle.attach(MetricsDao.class);

        metricsDao.createMetricsPartitions();

        final Integer retentionDays = configPropertyDao.getValue(MAINTENANCE_METRICS_RETENTION_DAYS, Integer.class);
        final Duration retentionDuration = Duration.ofDays(retentionDays);

        final int numDeletedComponent = metricsDao.deleteComponentMetricsForRetentionDuration(retentionDuration);
        final int numDeletedProject = metricsDao.deleteProjectMetricsForRetentionDuration(retentionDuration);

        return new Statistics(retentionDuration, numDeletedComponent, numDeletedProject);
    }
}
