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

import org.dependencytrack.event.maintenance.ProjectMaintenanceEvent;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_DAYS;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_TYPE;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_VERSIONS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public final class ProjectMaintenanceTask extends AbstractBatchingMaintenanceTask<ProjectMaintenanceEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectMaintenanceTask.class);
    private static final long ADVISORY_LOCK_ID = 7102463598274163180L;
    private static final int BATCH_SIZE = 100;
    private static final int MAX_ITERATIONS = 1000;

    public ProjectMaintenanceTask() {
        super(
                ProjectMaintenanceEvent.class,
                "project maintenance",
                ADVISORY_LOCK_ID,
                MAX_ITERATIONS);
    }

    @Override
    String doRun() {
        final Optional<String> retentionType = withJdbiHandle(
                handle -> handle
                        .attach(ConfigPropertyDao.class)
                        .getOptionalValue(MAINTENANCE_PROJECTS_RETENTION_TYPE, String.class));

        if (retentionType.isEmpty() || retentionType.get().isEmpty()) {
            return "inactive project deletion is disabled";
        }

        if ("AGE".equals(retentionType.get())) {
            final int retentionDays = withJdbiHandle(
                    handle -> handle
                            .attach(ConfigPropertyDao.class)
                            .getValue(MAINTENANCE_PROJECTS_RETENTION_DAYS, Integer.class));
            final Instant retentionCutOff = Instant.now().minus(Duration.ofDays(retentionDays));
            final int deleted = runBatched(BATCH_SIZE, handle -> {
                final List<ProjectDao.DeletedProject> deletedProjects = handle
                        .attach(ProjectDao.class)
                        .deleteInactiveProjectsForRetentionDuration(retentionCutOff, BATCH_SIZE);
                logDeletedProjects(deletedProjects);
                return deletedProjects.size();
            });

            return "deleted %d inactive projects by age".formatted(deleted);
        }

        final int versionCountThreshold = withJdbiHandle(
                handle -> handle
                        .attach(ConfigPropertyDao.class)
                        .getValue(MAINTENANCE_PROJECTS_RETENTION_VERSIONS, Integer.class));

        final int[] deletedVersions = new int[1];

        runBatched(BATCH_SIZE, handle -> {
            final var projectDao = handle.attach(ProjectDao.class);
            final List<String> projectBatch = projectDao.getDistinctProjects(versionCountThreshold, BATCH_SIZE);

            for (final String projectName : projectBatch) {
                final List<ProjectDao.DeletedProject> deleted =
                        projectDao.retainLastXInactiveProjects(projectName, versionCountThreshold);
                deletedVersions[0] += deleted.size();
                logDeletedProjects(deleted);
            }

            return projectBatch.size();
        });

        return "deleted %d excess project versions".formatted(deletedVersions[0]);
    }

    private static void logDeletedProjects(List<ProjectDao.DeletedProject> deletedProjects) {
        deletedProjects.forEach(deletedProject -> LOGGER.info(
                "Inactive project deleted: [name:{}, version:{}, inactive since:{}, uuid:{}]",
                deletedProject.name(),
                deletedProject.version(),
                deletedProject.inactiveSince(),
                deletedProject.uuid()));
    }

}
