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

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.dependencytrack.dex.engine.persistence.LeaseDao;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

final class DexEngineLeaderElection implements Closeable {

    private static final String LEASE_NAME = "leadership";
    private static final Logger LOGGER = LoggerFactory.getLogger(DexEngineLeaderElection.class);

    private final String instanceId;
    private final Jdbi jdbi;
    private final Duration leaseDuration;
    private final Duration checkInterval;
    private final MeterRegistry meterRegistry;

    private @Nullable ScheduledExecutorService executor;
    private @Nullable Counter leadershipAcquiredCounter;
    private @Nullable Counter leadershipLostCounter;
    private volatile boolean isLeader;

    DexEngineLeaderElection(
            String instanceId,
            Jdbi jdbi,
            Duration leaseDuration,
            Duration checkInterval,
            MeterRegistry meterRegistry) {
        this.instanceId = instanceId;
        this.jdbi = jdbi;
        this.leaseDuration = leaseDuration;
        this.checkInterval = checkInterval;
        this.meterRegistry = meterRegistry;
    }

    void start() {
        Gauge
                .builder("dt.dex.engine.leadership.status", this, it -> it.isLeader ? 1 : 0)
                .register(meterRegistry);

        leadershipAcquiredCounter = Counter
                .builder("dt.dex.engine.leadership.acquired")
                .register(meterRegistry);

        leadershipLostCounter = Counter
                .builder("dt.dex.engine.leadership.lost")
                .register(meterRegistry);

        executor = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform()
                        .name(getClass().getSimpleName())
                        .factory());
        executor.scheduleAtFixedRate(
                this::checkAndRenewLease,
                0,
                checkInterval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                LOGGER.warn("Interrupted while waiting for executor to stop", e);
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        if (isLeader) {
            try {
                jdbi.useTransaction(handle -> new LeaseDao(handle).releaseLease(LEASE_NAME, instanceId));
            } catch (RuntimeException e) {
                LOGGER.warn("Failed to release leadership lease");
            }
            isLeader = false;
        }
    }

    boolean isLeader() {
        return isLeader;
    }

    private void checkAndRenewLease() {
        try {
            final boolean leaseAcquired = jdbi.inTransaction(
                    handle -> new LeaseDao(handle).tryAcquireLease(
                            LEASE_NAME, instanceId, leaseDuration));

            if (leaseAcquired && !isLeader) {
                LOGGER.info("Leadership lease acquired");
                leadershipAcquiredCounter.increment();
                isLeader = true;
            } else if (!leaseAcquired && isLeader) {
                LOGGER.info("Leadership lease lost");
                leadershipLostCounter.increment();
                isLeader = false;
            } else if (leaseAcquired) {
                LOGGER.debug("Leadership lease renewed");
            } else {
                LOGGER.debug("Leadership lease held by another instance");
            }
        } catch (RuntimeException e) {
            if (isLeader) {
                LOGGER.error("Failed to renew lease; Assuming it to be lost", e);
                isLeader = false;
            } else {
                LOGGER.error("Failed to check lease", e);
            }
        }
    }

}
