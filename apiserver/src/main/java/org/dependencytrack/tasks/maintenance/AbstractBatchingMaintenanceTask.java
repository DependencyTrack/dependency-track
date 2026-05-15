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
import org.dependencytrack.persistence.jdbi.AdvisoryLocks;
import org.jdbi.v3.core.Handle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;
import java.util.function.ToIntFunction;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

abstract class AbstractBatchingMaintenanceTask<E extends Event> implements Subscriber {

    private final Class<E> eventType;
    private final String taskName;
    private final long advisoryLockId;
    private final int maxIterations;
    private final Logger logger;

    AbstractBatchingMaintenanceTask(
            Class<E> eventType,
            String taskName,
            long advisoryLockId,
            int maxIterations) {
        this.eventType = eventType;
        this.taskName = taskName;
        this.advisoryLockId = advisoryLockId;
        this.maxIterations = maxIterations;
        this.logger = LoggerFactory.getLogger(getClass());
    }

    @Override
    public final void inform(Event event) {
        if (!eventType.isInstance(event)) {
            return;
        }

        final long startTimeNanos = System.nanoTime();
        try {
            logger.info("Starting {}", taskName);
            final String summary = doRun();

            logger.info(
                    "Completed {} in {}ms: {}",
                    taskName,
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTimeNanos),
                    summary);
        } catch (RuntimeException e) {
            logger.error(
                    "Failed to complete {} after {}ms",
                    taskName,
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTimeNanos),
                    e);
        }
    }

    abstract String doRun();

    final int runBatched(int batchSize, ToIntFunction<Handle> batchFn) {
        int totalProcessed = 0;
        int iteration = 0;

        while (iteration < maxIterations) {
            final int processed = inJdbiTransaction(handle -> {
                if (!AdvisoryLocks.tryAcquire(handle, advisoryLockId)) {
                    return -1;
                }

                return batchFn.applyAsInt(handle);
            });

            if (processed < 0) {
                logger.debug("Advisory lock held by another instance; Skipping remaining batches");
                break;
            }

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
