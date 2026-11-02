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
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class WatermarkManagerTest {

    private final KeyValueStore kvStore = new MockKeyValueStore();

    private static String hash(final String value) {
        return org.apache.commons.codec.digest.DigestUtils.sha256Hex(value).substring(0, 12);
    }

    @Test
    void createShouldInitializeWatermarkWhenAvailable() {
        final String dataUrl = "https://example.com/osv-vulnerabilities";
        kvStore.putMany(Map.ofEntries(
                Map.entry(
                        "watermark/" + hash(dataUrl) + "/maven",
                        String.valueOf(Instant.ofEpochSecond(666).toEpochMilli())),
                Map.entry(
                        "watermark/" + hash(dataUrl) + "/npm",
                        String.valueOf(Instant.ofEpochSecond(555).toEpochMilli()))));

        final var watermarkManager = new WatermarkManager(dataUrl, List.of("maven", "npm"), kvStore);
        assertThat(watermarkManager).isNotNull();
        assertThat(watermarkManager.getWatermark("maven")).isEqualTo(Instant.ofEpochSecond(666));
        assertThat(watermarkManager.getWatermark("npm")).isEqualTo(Instant.ofEpochSecond(555));
    }

    @Test
    void createShouldNotInitializeWatermarkWhenNotAvailable() {
        final var watermarkManager = new WatermarkManager("https://example.com/osv-vulnerabilities", List.of("maven"), kvStore);
        assertThat(watermarkManager).isNotNull();
        assertThat(watermarkManager.getWatermark("maven")).isNull();
    }

    @Test
    void shouldUseSourceUrlForWatermarkKey() {
        final String originalUrl = "https://a.example.com";
        final String newUrl = "https://b.example.com";
        kvStore.put("watermark/" + hash(originalUrl) + "/maven", String.valueOf(Instant.ofEpochSecond(666).toEpochMilli()));

        final var watermarkManager = new WatermarkManager(newUrl, List.of("maven"), kvStore);
        assertThat(watermarkManager.getWatermark("maven")).isNull();
    }

    @Test
    void shouldAdvanceWatermarkWhenInitialWatermarkIsNull() {
        final var watermarkManager = new WatermarkManager("https://example.com/osv-vulnerabilities", List.of("maven"), kvStore);

        watermarkManager.maybeAdvance("maven", Instant.ofEpochSecond(666));
        assertThat(watermarkManager.getWatermark("maven")).isNull();

        watermarkManager.maybeCommit(List.of("maven"));
        assertThat(watermarkManager.getWatermark("maven")).isEqualTo(Instant.ofEpochSecond(666));
    }

    @Test
    void shouldAdvanceWatermarkWhenInitialWatermarkIsEarlier() {
        final String dataUrl = "https://example.com/osv-vulnerabilities";
        kvStore.put(
                "watermark/" + hash(dataUrl) + "/maven",
                String.valueOf(Instant.ofEpochSecond(666).toEpochMilli()));

        final var watermarkManager = new WatermarkManager(dataUrl, List.of("maven"), kvStore);

        watermarkManager.maybeAdvance("maven", Instant.ofEpochSecond(667));
        assertThat(watermarkManager.getWatermark("maven")).isEqualTo(Instant.ofEpochSecond(666));

        watermarkManager.maybeCommit(List.of("maven"));
        assertThat(watermarkManager.getWatermark("maven")).isEqualTo(Instant.ofEpochSecond(667));
    }
}
