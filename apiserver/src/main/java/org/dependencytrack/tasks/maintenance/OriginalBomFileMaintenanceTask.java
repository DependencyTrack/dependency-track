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

import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.model.BomRetentionPolicy;
import org.dependencytrack.persistence.jdbi.BomDao;
import org.dependencytrack.persistence.jdbi.ConfigPropertyDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.dependencytrack.filestorage.OriginalBomFileDeletion.scheduleOriginalBomFileDeletion;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_ORIGINAL_EXPIRATION_DAYS;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_ORIGINAL_RETENTION_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_ORIGINAL_RETENTION_POLICY;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.3.0
 */
public final class OriginalBomFileMaintenanceTask extends AbstractBatchingMaintenanceTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(OriginalBomFileMaintenanceTask.class);
    private static final int BATCH_SIZE = 100;
    private static final int MAX_ITERATIONS = 1000;

    private final DexEngine dexEngine;

    public OriginalBomFileMaintenanceTask(final DexEngine dexEngine) {
        super(MAX_ITERATIONS);
        this.dexEngine = dexEngine;
    }

    @Override
    public void run() {
        final int expirationDays = withJdbiHandle(handle -> getExpirationDays(handle.attach(ConfigPropertyDao.class)));
        if (expirationDays <= 0) {
            LOGGER.debug("Age-based BOM retention is not active; Nothing to do");
            return;
        }

        final Instant cutoff = Instant.now().minus(Duration.ofDays(expirationDays));
        final int cleared = runBatched(
                BATCH_SIZE,
                handle -> handle.attach(BomDao.class).clearExpiredOriginalFileMetadata(cutoff, BATCH_SIZE),
                List::size,
                clearedFiles -> scheduleOriginalBomFileDeletion(dexEngine, clearedFiles));

        if (cleared > 0) {
            LOGGER.info("Scheduled deletion of {} expired original BOM file(s)", cleared);
        }
    }

    private static int getExpirationDays(final ConfigPropertyDao configPropertyDao) {
        if (!configPropertyDao.isEnabled(BOM_ORIGINAL_RETENTION_ENABLED)) {
            return 0;
        }
        final String policy = configPropertyDao
                .getOptionalValue(BOM_ORIGINAL_RETENTION_POLICY)
                .orElseGet(BOM_ORIGINAL_RETENTION_POLICY::getDefaultPropertyValue);
        if (BomRetentionPolicy.valueOf(policy) != BomRetentionPolicy.AGE_BASED) {
            return 0;
        }
        return configPropertyDao
                .getOptionalValue(BOM_ORIGINAL_EXPIRATION_DAYS, Integer.class)
                .orElseGet(() -> Integer.parseInt(BOM_ORIGINAL_EXPIRATION_DAYS.getDefaultPropertyValue()));
    }
}
