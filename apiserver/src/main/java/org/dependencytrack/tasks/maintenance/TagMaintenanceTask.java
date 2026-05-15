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

import org.dependencytrack.event.maintenance.TagMaintenanceEvent;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.dependencytrack.persistence.jdbi.TagDao;

import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_TAGS_DELETE_UNUSED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.0.0
 */
public final class TagMaintenanceTask extends AbstractBatchingMaintenanceTask<TagMaintenanceEvent> {

    private static final long ADVISORY_LOCK_ID = 5827314498267091435L;
    private static final int BATCH_SIZE = 1000;
    private static final int MAX_ITERATIONS = 1000;

    public TagMaintenanceTask() {
        super(
                TagMaintenanceEvent.class,
                "tag maintenance",
                ADVISORY_LOCK_ID,
                MAX_ITERATIONS);
    }

    @Override
    String doRun() {
        final boolean deleteUnusedEnabled = withJdbiHandle(handle -> handle
                .attach(ConfigPropertyDao.class)
                .getValue(MAINTENANCE_TAGS_DELETE_UNUSED, Boolean.class));
        if (!deleteUnusedEnabled) {
            return "unused tag deletion is disabled";
        }

        final int deleted = runBatched(
                BATCH_SIZE,
                handle -> handle.attach(TagDao.class).deleteUnused(BATCH_SIZE));
        return "deleted %d unused tags".formatted(deleted);
    }

}
