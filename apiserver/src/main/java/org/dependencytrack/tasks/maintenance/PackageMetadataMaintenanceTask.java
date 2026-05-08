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
import org.dependencytrack.event.maintenance.PackageMetadataMaintenanceEvent;
import org.jdbi.v3.core.Handle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static net.javacrumbs.shedlock.core.LockAssert.assertLocked;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.util.LockProvider.executeWithLock;
import static org.dependencytrack.util.TaskUtil.getLockConfigForTask;

/**
 * @since 5.0.0
 */
public class PackageMetadataMaintenanceTask implements Subscriber {

    private static final Logger LOGGER = LoggerFactory.getLogger(PackageMetadataMaintenanceTask.class);

    @Override
    public void inform(final Event event) {
        if (!(event instanceof PackageMetadataMaintenanceEvent)) {
            return;
        }

        final long startTimeNs = System.nanoTime();
        try (final Handle jdbiHandle = openJdbiHandle()) {
            LOGGER.info("Starting component metadata maintenance");
            final Statistics statistics = executeWithLock(
                    getLockConfigForTask(PackageMetadataMaintenanceTask.class),
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
            int deletedIntegrityMetadata,
            int deletedRepositoryMetadata) {
    }

    private Statistics informLocked(final Handle jdbiHandle) {
        assertLocked();

        final int numDeletedPackageVersionMetadata = jdbiHandle
                .createUpdate("""
                        DELETE
                          FROM "PACKAGE_ARTIFACT_METADATA" AS pam
                         WHERE NOT EXISTS (
                           SELECT 1
                             FROM "COMPONENT" AS c
                            WHERE c."PURL" = pam."PURL"
                         )
                        """)
                .execute();

        final int numDeletedPackageMetadata = jdbiHandle
                .createUpdate("""
                        DELETE
                          FROM "PACKAGE_METADATA" AS pm
                         WHERE NOT EXISTS (
                           SELECT 1
                             FROM "PACKAGE_ARTIFACT_METADATA" AS pam
                            WHERE pam."PACKAGE_PURL" = pm."PURL"
                         )
                        """)
                .execute();

        return new Statistics(
                numDeletedPackageVersionMetadata,
                numDeletedPackageMetadata);
    }

}
