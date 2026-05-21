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
import org.dependencytrack.persistence.jdbi.TagDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_TAGS_DELETE_UNUSED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
public final class TagMaintenanceTask extends AbstractBatchingMaintenanceTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(TagMaintenanceTask.class);
    private static final int BATCH_SIZE = 1000;
    private static final int MAX_ITERATIONS = 1000;

    public TagMaintenanceTask() {
        super(MAX_ITERATIONS);
    }

    @Override
    public void run() {
        final boolean deleteUnusedEnabled = withJdbiHandle(handle -> handle
                .attach(ConfigPropertyDao.class)
                .getValue(MAINTENANCE_TAGS_DELETE_UNUSED, Boolean.class));
        if (!deleteUnusedEnabled) {
            LOGGER.debug("Unused tag deletion is disabled; nothing to do");
            return;
        }

        final int deleted = runBatched(
                BATCH_SIZE,
                handle -> handle.attach(TagDao.class).deleteUnused(BATCH_SIZE));
        if (deleted > 0) {
            LOGGER.info("Deleted {} unused tags", deleted);
        }
    }

}
