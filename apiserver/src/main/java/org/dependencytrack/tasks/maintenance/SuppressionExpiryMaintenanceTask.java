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

import org.dependencytrack.persistence.jdbi.AnalysisDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Un-suppresses findings whose suppression expiry has passed.
 *
 * @since 5.2.0
 */
public final class SuppressionExpiryMaintenanceTask extends AbstractBatchingMaintenanceTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(SuppressionExpiryMaintenanceTask.class);
    private static final int BATCH_SIZE = 1000;
    private static final int MAX_ITERATIONS = 1000;

    public SuppressionExpiryMaintenanceTask() {
        super(MAX_ITERATIONS);
    }

    @Override
    public void run() {
        final int expired = runBatched(BATCH_SIZE, handle -> {
            final var analysisDao = new AnalysisDao(handle);

            final List<Long> analysisIds = analysisDao.expireSuppressions(BATCH_SIZE);
            if (analysisIds.isEmpty()) {
                return 0;
            }

            // Record the un-suppression in the audit trail, so it is not mistaken
            // for a manual decision.
            analysisDao.createComments(analysisIds.stream()
                    .map(analysisId -> new AnalysisDao.CreateCommentCommand(analysisId, null, "Unsuppressed"))
                    .toList());

            return analysisIds.size();
        });

        if (expired > 0) {
            LOGGER.info("Un-suppressed {} finding(s) whose suppression expiry has elapsed", expired);
        }
    }
}
