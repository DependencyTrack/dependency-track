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
package org.dependencytrack.vulndatasource.nvd;

import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @since 5.0.0
 */
final class WatermarkManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(WatermarkManager.class);
    private static final String FEED_DIGEST_KEY_PREFIX = "feed-digest:";

    private final KeyValueStore kvStore;
    private Instant committedWatermark;
    private Instant pendingWatermark;
    private Long committedWatermarkVersion;
    private final Map<String, String> committedFeedDigests;
    private final Map<String, Long> committedFeedDigestVersions;
    private final Map<String, String> pendingFeedDigests;

    private WatermarkManager(
            final KeyValueStore kvStore,
            final Instant committedWatermark,
            final Long committedWatermarkVersion,
            final Map<String, String> committedFeedDigests,
            final Map<String, Long> committedFeedDigestVersions) {
        this.kvStore = kvStore;
        this.committedWatermark = committedWatermark;
        this.committedWatermarkVersion = committedWatermarkVersion;
        this.committedFeedDigests = committedFeedDigests;
        this.committedFeedDigestVersions = committedFeedDigestVersions;
        this.pendingFeedDigests = new HashMap<>();
    }

    // TODO: Just use constructor after upgrading to Java 25: https://openjdk.org/jeps/513
    static WatermarkManager create(final KeyValueStore kvStore, final Collection<String> feedNames) {
        Instant committedWatermark = null;
        Long committedWatermarkVersion = null;

        final KeyValueStore.Entry watermarkEntry = kvStore.get("watermark");
        if (watermarkEntry != null) {
            try {
                committedWatermark = Instant.ofEpochMilli(
                        Long.parseLong(watermarkEntry.value()));
                committedWatermarkVersion = watermarkEntry.version();
            } catch (NumberFormatException ex) {
                LOGGER.warn("Encountered invalid watermark: {}; Ignoring", watermarkEntry, ex);
            }
        }

        final var committedFeedDigests = new HashMap<String, String>();
        final var committedFeedDigestVersions = new HashMap<String, Long>();

        if (!feedNames.isEmpty()) {
            final Map<String, String> feedNameByKey = feedNames.stream()
                    .collect(Collectors.toMap(
                            name -> FEED_DIGEST_KEY_PREFIX + name,
                            name -> name));

            final Map<String, KeyValueStore.Entry> entries = kvStore.getMany(feedNameByKey.keySet());
            for (final Map.Entry<String, KeyValueStore.Entry> entry : entries.entrySet()) {
                final String feedName = feedNameByKey.get(entry.getKey());
                committedFeedDigests.put(feedName, entry.getValue().value());
                committedFeedDigestVersions.put(feedName, entry.getValue().version());
            }
        }

        return new WatermarkManager(
                kvStore, committedWatermark, committedWatermarkVersion,
                committedFeedDigests, committedFeedDigestVersions);
    }

    Instant getWatermark() {
        return committedWatermark;
    }

    @Nullable String getFeedDigest(final String feedName) {
        return committedFeedDigests.get(feedName);
    }

    void recordFeedDigest(final String feedName, final String sha256) {
        pendingFeedDigests.put(feedName, sha256);
    }

    void commitFeedDigests() {
        if (pendingFeedDigests.isEmpty()) {
            return;
        }

        for (final Map.Entry<String, String> entry : pendingFeedDigests.entrySet()) {
            final String feedName = entry.getKey();
            final String sha256 = entry.getValue();
            final String existingDigest = committedFeedDigests.get(feedName);
            if (sha256.equals(existingDigest)) {
                continue;
            }

            final String key = FEED_DIGEST_KEY_PREFIX + feedName;
            final Long expectedVersion = committedFeedDigestVersions.get(feedName);

            LOGGER.debug("Committing feed digest for {} to KV store", feedName);
            final CompareAndPutResult result = kvStore.compareAndPut(key, sha256, expectedVersion);
            switch (result) {
                case CompareAndPutResult.Success(long newVersion) -> {
                    committedFeedDigests.put(feedName, sha256);
                    committedFeedDigestVersions.put(feedName, newVersion);
                }
                case CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason reason) ->
                        throw new IllegalStateException(
                                "Failed to commit feed digest for %s to KV store: %s".formatted(
                                        feedName, reason));
            }
        }

        pendingFeedDigests.clear();
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

    void maybeCommit() {
        if (pendingWatermark == null
                || (committedWatermark != null && committedWatermark.equals(pendingWatermark))) {
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
                pendingWatermark = null;
            }
            case CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason reason) ->
                    throw new IllegalStateException(
                            "Failed to commit watermark %s to KV store: %s".formatted(
                                    pendingWatermark, reason));
        }
    }

}
