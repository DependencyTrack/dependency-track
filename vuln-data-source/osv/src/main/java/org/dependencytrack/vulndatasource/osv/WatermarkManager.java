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
package org.dependencytrack.vulndatasource.osv;

import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * @since 5.0.0
 */
final class WatermarkManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(WatermarkManager.class);

    private final WatermarkStore store;
    private final Map<String, WatermarkRecord> pendingRecordByEcosystem;
    private final Map<String, WatermarkRecord> committedRecordByEcosystem;

    WatermarkManager(
            final Collection<String> ecosystems,
            final KeyValueStore kvStore) {
        final var watermarkStore = new WatermarkStore(kvStore);
        final Map<String, WatermarkRecord> recordByEcosystem =
                watermarkStore.getForEcosystems(ecosystems);

        this.store = watermarkStore;
        this.pendingRecordByEcosystem = new HashMap<>(recordByEcosystem);
        this.committedRecordByEcosystem = new HashMap<>(recordByEcosystem);
    }

    Instant getWatermark(final String ecosystem) {
        final WatermarkRecord record = committedRecordByEcosystem.get(ecosystem);
        return record != null ? record.value() : null;
    }

    void maybeAdvance(final String ecosystem, final Instant watermark) {
        pendingRecordByEcosystem.compute(ecosystem, (_, existingRecord) -> {
            if (existingRecord == null) {
                return new WatermarkRecord(ecosystem, watermark);
            } else if (existingRecord.value().isAfter(watermark)) {
                return existingRecord;
            }

            return new WatermarkRecord(ecosystem, watermark, existingRecord.version());
        });
    }

    void maybeCommit(final Collection<String> ecosystems) {
        for (final String ecosystem : ecosystems) {
            final WatermarkRecord pendingRecord = pendingRecordByEcosystem.get(ecosystem);
            if (pendingRecord == null) {
                continue;
            }

            WatermarkRecord committedRecord = committedRecordByEcosystem.get(ecosystem);
            if (committedRecord != null && !committedRecord.value().isBefore(pendingRecord.value())) {
                LOGGER.debug(
                        "Pending watermark {} is not newer than last committed {}",
                        pendingRecord.value(),
                        committedRecord.value());
                continue;
            }

            LOGGER.debug("Committing watermark {} for ecosystem {}", pendingRecord.value(), ecosystem);
            committedRecord = store.save(pendingRecord);
            committedRecordByEcosystem.put(ecosystem, committedRecord);
            pendingRecordByEcosystem.put(ecosystem, committedRecord);
        }
    }


}