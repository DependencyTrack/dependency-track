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
package org.dependencytrack.vulndatasource.github;

import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
final class WatermarkManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(WatermarkManager.class);
    private static final Duration MIN_COMMIT_INTERVAL = Duration.ofSeconds(3);

    private final Clock clock;
    private final KeyValueStore kvStore;
    private Instant committedWatermark;
    private Long committedWatermarkVersion;
    private Instant pendingWatermark;
    private Instant lastCommittedAt;

    private WatermarkManager(
            final Clock clock,
            final KeyValueStore kvStore,
            final Instant committedWatermark,
            final Long committedWatermarkVersion) {
        this.clock = clock;
        this.kvStore = kvStore;
        this.committedWatermark = committedWatermark;
        this.committedWatermarkVersion = committedWatermarkVersion;
        this.pendingWatermark = committedWatermark;
        this.lastCommittedAt = Instant.now(clock);
    }

    static WatermarkManager create(final Clock clock, final KeyValueStore kvStore) {
        requireNonNull(clock, "clock must not be null");
        requireNonNull(kvStore, "kvStore must not be null");

        final KeyValueStore.Entry watermarkEntry = kvStore.get("watermark");
        if (watermarkEntry != null) {
            try {
                final Instant committedWatermark = Instant.ofEpochMilli(Long.parseLong(watermarkEntry.value()));
                return new WatermarkManager(clock, kvStore, committedWatermark, watermarkEntry.version());
            } catch (NumberFormatException ex) {
                LOGGER.warn("Encountered invalid watermark: {}; Ignoring", watermarkEntry, ex);
            }
        }

        return new WatermarkManager(clock, kvStore, null, null);
    }

    Instant getWatermark() {
        return committedWatermark;
    }

    void maybeAdvance(final Instant watermark) {
        if (watermark == null) {
            return;
        }
        if (pendingWatermark == null || pendingWatermark.isBefore(watermark)) {
            LOGGER.debug("Advancing watermark from {} to {}", pendingWatermark, watermark);
            pendingWatermark = watermark;
        }
    }

    void maybeCommit(final boolean ignoreMinCommitInterval) {
        if (pendingWatermark == null
                || (committedWatermark != null && committedWatermark.equals(pendingWatermark))) {
            return;
        }
        if (!ignoreMinCommitInterval
                && Duration.between(lastCommittedAt, Instant.now(clock)).compareTo(MIN_COMMIT_INTERVAL) < 0) {
            return;
        }

        LOGGER.debug("Committing watermark {} to KV store", pendingWatermark);
        final CompareAndPutResult capResult = kvStore.compareAndPut(
                "watermark",
                String.valueOf(pendingWatermark.toEpochMilli()),
                committedWatermarkVersion);
        switch (capResult) {
            case CompareAndPutResult.Success(long newVersion) -> {
                committedWatermark = pendingWatermark;
                committedWatermarkVersion = newVersion;
                lastCommittedAt = Instant.now(clock);
            }
            case CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason reason) ->
                    throw new IllegalStateException(
                            "Failed to commit watermark %s to KV store: %s".formatted(
                                    pendingWatermark, reason));
        }
    }

}
