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

import org.jdbi.v3.core.Handle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.ToIntFunction;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

abstract class AbstractBatchingMaintenanceTask implements Runnable {

    private final int maxIterations;
    private final Logger logger;

    AbstractBatchingMaintenanceTask(int maxIterations) {
        this.maxIterations = maxIterations;
        this.logger = LoggerFactory.getLogger(getClass());
    }

    final int runBatched(int batchSize, ToIntFunction<Handle> batchFn) {
        int totalProcessed = 0;
        int iteration = 0;

        while (iteration < maxIterations) {
            final int processed = inJdbiTransaction(batchFn::applyAsInt);

            iteration++;
            totalProcessed += processed;
            if (processed < batchSize) {
                break;
            }
        }

        if (iteration >= maxIterations) {
            logger.warn("Reached safety cap of {} iterations; will resume on next run", maxIterations);
        }

        return totalProcessed;
    }

}
