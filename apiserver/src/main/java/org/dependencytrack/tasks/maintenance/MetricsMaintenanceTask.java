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

import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.jdbi.v3.core.Handle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_METRICS_RETENTION_DAYS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

/**
 * @since 5.0.0
 */
public final class MetricsMaintenanceTask implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(MetricsMaintenanceTask.class);

    @Override
    public void run() {
        useJdbiHandle(this::runMaintenance);
    }

    private void runMaintenance(final Handle jdbiHandle) {
        final var configPropertyDao = jdbiHandle.attach(ConfigPropertyDao.class);
        final var metricsDao = jdbiHandle.attach(MetricsDao.class);

        metricsDao.createMetricsPartitions();

        final Integer retentionDays = configPropertyDao.getValue(MAINTENANCE_METRICS_RETENTION_DAYS, Integer.class);
        final Duration retentionDuration = Duration.ofDays(retentionDays);
        LOGGER.debug("Configured retention duration: {}", retentionDuration);

        final int numDeletedComponent = metricsDao.deleteComponentMetricsForRetentionDuration(retentionDuration);
        if (numDeletedComponent > 0) {
            LOGGER.info("Dropped {} component metrics partition(s)", numDeletedComponent);
        }

        final int numDeletedProject = metricsDao.deleteProjectMetricsForRetentionDuration(retentionDuration);
        if (numDeletedProject > 0) {
            LOGGER.info("Dropped {} project metrics partition(s)", numDeletedProject);
        }
    }

}
