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

import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.ToIntFunction;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

abstract class AbstractBatchingMaintenanceTask implements Runnable {

    private final int maxIterations;
    private final Logger logger;

    AbstractBatchingMaintenanceTask(int maxIterations) {
        this.maxIterations = maxIterations;
        this.logger = LoggerFactory.getLogger(getClass());
    }

    final int runBatched(
            final int batchSize,
            final ToIntFunction<Handle> batchFn) {
        return runBatched(
                batchSize,
                handle -> batchFn.applyAsInt(handle),
                result -> result,
                result -> {
                });
    }

    final <T> int runBatched(
            final int batchSize,
            final Function<Handle, T> batchFn,
            final ToIntFunction<T> processedCountFn,
            final Consumer<T> afterCommitFn) {
        int totalProcessed = 0;
        int iteration = 0;

        while (iteration < maxIterations) {
            final T batchResult =
                    inJdbiTransaction(batchFn::apply);

            afterCommitFn.accept(batchResult);

            final int processed =
                    processedCountFn.applyAsInt(batchResult);

            iteration++;
            totalProcessed += processed;
            if (processed < batchSize) {
                break;
            }
        }

        if (iteration >= maxIterations) {
            logger.warn(
                    "Reached safety cap of {} iterations; "
                            + "will resume on next run",
                    maxIterations);
        }

        return totalProcessed;
    }

}
