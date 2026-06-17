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
package org.dependencytrack.dex.engine;

import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

final class MaintenanceWorker implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(MaintenanceWorker.class);

    private final Jdbi jdbi;
    private final Supplier<Boolean> leadershipSupplier;
    private final Duration runRetentionDuration;
    private final int runDeletionBatchSize;
    private final Duration initialDelay;
    private final Duration interval;
    private @Nullable ScheduledExecutorService executor;

    MaintenanceWorker(
            Jdbi jdbi,
            Supplier<Boolean> leadershipSupplier,
            Duration runRetentionDuration,
            int runDeletionBatchSize,
            Duration initialDelay,
            Duration interval) {
        this.jdbi = jdbi;
        this.leadershipSupplier = leadershipSupplier;
        this.runRetentionDuration = runRetentionDuration;
        this.runDeletionBatchSize = runDeletionBatchSize;
        this.initialDelay = initialDelay;
        this.interval = interval;
    }

    void start() {
        executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name(MaintenanceWorker.class.getSimpleName())
                        .factory());
        executor.scheduleAtFixedRate(
                () -> {
                    try {
                        enforceRunRetention();
                    } catch (RuntimeException e) {
                        LOGGER.error("Failed to perform maintenance", e);
                    }
                },
                initialDelay.toMillis(),
                interval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (executor != null) {
            executor.close();
        }
    }

    private void enforceRunRetention() {
        if (!leadershipSupplier.get()) {
            LOGGER.debug("Not the leader; Skipping");
            return;
        }

        LOGGER.debug("Enforcing run retention");

        jdbi.useTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    with cte_candidates as (
                      select id
                        from dex_workflow_run
                       where completed_at < (NOW() - (:retentionDuration))
                       order by completed_at
                       limit :batchSize
                         for no key update
                        skip locked
                    )
                    delete from dex_workflow_run
                     where id in (select id from cte_candidates)
                    """);

            final int runsDeleted = update
                    .bind("retentionDuration", runRetentionDuration)
                    .bind("batchSize", runDeletionBatchSize)
                    .execute();

            if (runsDeleted > 0) {
                LOGGER.info("Deleted {} completed workflow run(s)", runsDeleted);
            } else {
                LOGGER.debug("No completed workflow runs deleted");
            }
        });
    }

}
