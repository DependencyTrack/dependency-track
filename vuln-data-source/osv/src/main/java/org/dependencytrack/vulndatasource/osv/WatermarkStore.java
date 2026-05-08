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

import org.dependencytrack.plugin.api.storage.CompareAndPutResult;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * @since 5.0.0
 */
final class WatermarkStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(WatermarkStore.class);

    private final KeyValueStore kvStore;

    WatermarkStore(final KeyValueStore kvStore) {
        this.kvStore = kvStore;
    }

    Map<String, WatermarkRecord> getForEcosystems(final Collection<String> ecosystems) {
        final Map<String, String> ecosystemByKey = ecosystems.stream()
                .collect(Collectors.toMap(
                        WatermarkStore::getKey,
                        Function.identity()));

        final Map<String, KeyValueStore.Entry> kvEntryByKey = kvStore.getMany(ecosystemByKey.keySet());
        if (kvEntryByKey.isEmpty()) {
            return Collections.emptyMap();
        }

        final var result = new HashMap<String, WatermarkRecord>(kvEntryByKey.size());
        for (final Map.Entry<String, KeyValueStore.Entry> mapEntry : kvEntryByKey.entrySet()) {
            final String kvKey = mapEntry.getKey();
            final KeyValueStore.Entry kvEntry = mapEntry.getValue();
            final String ecosystem = ecosystemByKey.get(kvKey);

            final Instant watermark;
            try {
                watermark = Instant.ofEpochMilli(Long.parseLong(kvEntry.value()));
            } catch (NumberFormatException ex) {
                LOGGER.warn(
                        "Encountered invalid watermark for ecosystem {}: {}; Discarding",
                        ecosystem,
                        kvEntry.value(),
                        ex);
                continue;
            }

            result.put(ecosystem, new WatermarkRecord(
                    ecosystem, watermark, kvEntry.version()));
        }

        return result;
    }

    WatermarkRecord save(final WatermarkRecord watermark) {
        final CompareAndPutResult result = kvStore.compareAndPut(
                getKey(watermark.ecosystem()),
                String.valueOf(watermark.value().toEpochMilli()),
                watermark.version());

        return switch (result) {
            case CompareAndPutResult.Success(long newVersion) ->
                    new WatermarkRecord(watermark.ecosystem(), watermark.value(), newVersion);
            case CompareAndPutResult.Failure(CompareAndPutResult.Failure.Reason reason) ->
                    throw new IllegalStateException(
                            "Failed to save watermark %s to KV store: %s".formatted(
                                    watermark, reason));
        };
    }

    private static String getKey(final String ecosystem) {
        return "watermark/" + ecosystem;
    }

}
