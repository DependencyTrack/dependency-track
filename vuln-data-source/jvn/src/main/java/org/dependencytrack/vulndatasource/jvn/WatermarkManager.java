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
package org.dependencytrack.vulndatasource.jvn;

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
 * Persists mirror-run checkpoints via the plugin {@link KeyValueStore}: the sha256 digest of each
 * yearly detail feed (from {@code checksum.txt}), so subsequent runs skip unchanged years, and the
 * highest {@code datePublic} processed, as a progress indicator.
 * <p>
 * Adapted from the NVD data source's {@code WatermarkManager}.
 *
 * @since 5.1.0
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

    WatermarkManager(final KeyValueStore kvStore, final Collection<String> feedNames) {
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

        this.kvStore = kvStore;
        this.committedWatermark = committedWatermark;
        this.committedWatermarkVersion = committedWatermarkVersion;
        this.committedFeedDigests = committedFeedDigests;
        this.committedFeedDigestVersions = committedFeedDigestVersions;
        this.pendingFeedDigests = new HashMap<>();
    }

    @Nullable Instant getWatermark() {
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

    /** The digest committed for a feed on a previous run, or {@code null} if it was never seen. */
    @Nullable String getCommittedFeedDigest(final String feedName) {
        return committedFeedDigests.get(feedName);
    }

    /** Records the digest of a feed processed this run; persisted by {@link #maybeCommit()}. */
    void recordFeedDigest(final String feedName, final String digest) {
        pendingFeedDigests.put(feedName, digest);
    }

    void maybeCommit() {
        commitWatermark();
        commitFeedDigests();
    }

    private void commitWatermark() {
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

    private void commitFeedDigests() {
        for (final Map.Entry<String, String> pending : pendingFeedDigests.entrySet()) {
            final String feedName = pending.getKey();
            final String digest = pending.getValue();
            if (digest.equals(committedFeedDigests.get(feedName))) {
                continue;
            }
            final CompareAndPutResult capResult = kvStore.compareAndPut(
                    FEED_DIGEST_KEY_PREFIX + feedName,
                    digest,
                    committedFeedDigestVersions.get(feedName));
            switch (capResult) {
                case CompareAndPutResult.Success(long newVersion) -> {
                    committedFeedDigests.put(feedName, digest);
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

}
