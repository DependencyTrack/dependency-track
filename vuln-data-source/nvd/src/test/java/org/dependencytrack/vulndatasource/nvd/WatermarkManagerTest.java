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

import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WatermarkManagerTest {

    @Test
    void shouldLoadExistingWatermark() {
        final var kvStore = new MockKeyValueStore();
        kvStore.put("watermark", "1700000000000");

        final var manager = new WatermarkManager(kvStore, List.of());

        assertThat(manager.getWatermark()).isEqualTo(Instant.ofEpochMilli(1700000000000L));
    }

    @Test
    void shouldReturnNullWatermarkWhenNoneExists() {
        final var kvStore = new MockKeyValueStore();

        final var manager = new WatermarkManager(kvStore, List.of());

        assertThat(manager.getWatermark()).isNull();
    }

    @Test
    void shouldAdvanceAndCommitWatermark() {
        final var kvStore = new MockKeyValueStore();
        final var manager = new WatermarkManager(kvStore, List.of());

        final var watermark = Instant.ofEpochMilli(1700000000000L);
        manager.maybeAdvance(watermark);
        manager.maybeCommit();

        assertThat(manager.getWatermark()).isEqualTo(watermark);
        assertThat(kvStore.get("watermark").value()).isEqualTo("1700000000000");
    }

    @Test
    void shouldNotAdvanceToEarlierWatermark() {
        final var kvStore = new MockKeyValueStore();
        final var manager = new WatermarkManager(kvStore, List.of());

        final var later = Instant.ofEpochMilli(1700000000000L);
        final var earlier = Instant.ofEpochMilli(1600000000000L);
        manager.maybeAdvance(later);
        manager.maybeAdvance(earlier);
        manager.maybeCommit();

        assertThat(manager.getWatermark()).isEqualTo(later);
    }

    @Test
    void shouldLoadExistingFeedDigests() {
        final var kvStore = new MockKeyValueStore();
        kvStore.put("feed-digest:2024", "abc123");
        kvStore.put("feed-digest:modified", "def456");

        final var manager = new WatermarkManager(kvStore, List.of("2024", "2023", "modified"));

        assertThat(manager.getFeedDigest("2024")).isEqualTo("abc123");
        assertThat(manager.getFeedDigest("modified")).isEqualTo("def456");
        assertThat(manager.getFeedDigest("2023")).isNull();
    }

    @Test
    void shouldReturnNullForUnknownFeedDigest() {
        final var kvStore = new MockKeyValueStore();
        final var manager = new WatermarkManager(kvStore, List.of("2024"));

        assertThat(manager.getFeedDigest("1999")).isNull();
    }

    @Test
    void shouldCommitPendingFeedDigests() {
        final var kvStore = new MockKeyValueStore();
        final var manager = new WatermarkManager(kvStore, List.of("2024", "2023"));

        manager.recordFeedDigest("2024", "abc123");
        manager.recordFeedDigest("2023", "def456");
        manager.commitFeedDigests();

        assertThat(kvStore.get("feed-digest:2024").value()).isEqualTo("abc123");
        assertThat(kvStore.get("feed-digest:2023").value()).isEqualTo("def456");

        assertThat(manager.getFeedDigest("2024")).isEqualTo("abc123");
        assertThat(manager.getFeedDigest("2023")).isEqualTo("def456");
    }

    @Test
    void shouldNotCommitUnchangedDigests() {
        final var kvStore = new MockKeyValueStore();
        kvStore.put("feed-digest:2024", "abc123");

        final var manager = new WatermarkManager(kvStore, List.of("2024"));

        manager.recordFeedDigest("2024", "abc123");
        manager.commitFeedDigests();

        assertThat(kvStore.get("feed-digest:2024").version()).isEqualTo(0);
    }

    @Test
    void shouldUpdateExistingFeedDigest() {
        final var kvStore = new MockKeyValueStore();
        kvStore.put("feed-digest:2024", "old_digest");

        final var manager = new WatermarkManager(kvStore, List.of("2024"));

        manager.recordFeedDigest("2024", "new_digest");
        manager.commitFeedDigests();

        assertThat(kvStore.get("feed-digest:2024").value()).isEqualTo("new_digest");
        assertThat(manager.getFeedDigest("2024")).isEqualTo("new_digest");
    }

    @Test
    void shouldHandleEmptyFeedNameList() {
        final var kvStore = new MockKeyValueStore();
        final var manager = new WatermarkManager(kvStore, List.of());

        assertThat(manager.getFeedDigest("2024")).isNull();
    }

    @Test
    void shouldCommitFeedDigestsIndependentlyOfWatermark() {
        final var kvStore = new MockKeyValueStore();
        final var manager = new WatermarkManager(kvStore, List.of("2024"));

        manager.maybeAdvance(Instant.ofEpochMilli(1700000000000L));
        manager.recordFeedDigest("2024", "abc123");
        manager.commitFeedDigests();

        assertThat(kvStore.get("feed-digest:2024").value()).isEqualTo("abc123");
        assertThat(kvStore.get("watermark")).isNull();
    }

}
