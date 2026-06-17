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

import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.plugin.testing.MockKeyValueStore;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;

class WatermarkManagerTest {

    @Test
    void createShouldInitializeWatermarkWhenAvailable() {
        final var watermark = Instant.ofEpochSecond(666);

        final var keyValueStore = new MockKeyValueStore();
        putWatermark(keyValueStore, watermark);

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), keyValueStore);
        assertThat(watermarkManager).isNotNull();
        assertThat(watermarkManager.getWatermark()).isEqualTo(watermark);
    }

    @Test
    void createShouldNotInitializeWatermarkWhenNotAvailable() {
        final var keyValueStore = new MockKeyValueStore();

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), keyValueStore);
        assertThat(watermarkManager).isNotNull();
        assertThat(watermarkManager.getWatermark()).isNull();
    }

    @Test
    void shouldAdvanceWatermarkWhenInitialWatermarkIsEarlier() {
        final var keyValueStore = new MockKeyValueStore();
        putWatermark(keyValueStore, Instant.ofEpochSecond(666));

        final var watermarkManager = WatermarkManager.create(Clock.systemUTC(), keyValueStore);

        watermarkManager.maybeAdvance(Instant.ofEpochSecond(667));
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(666));

        watermarkManager.maybeCommit(true);
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(667));
    }

    @Test
    void maybeCommitShouldNotCommitWhenLastCommitWasLessThanThreeSecondsBack() {
        final var keyValueStore = new MockKeyValueStore();
        putWatermark(keyValueStore, Instant.ofEpochSecond(111));

        final var clock = new MutableClock(Instant.ofEpochSecond(666));
        final var watermarkManager = WatermarkManager.create(clock, keyValueStore);

        watermarkManager.maybeAdvance(Instant.ofEpochSecond(222));
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(111));

        watermarkManager.maybeCommit(false);
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(111));

        clock.advance(Duration.ofSeconds(3));
        watermarkManager.maybeCommit(false);
        assertThat(watermarkManager.getWatermark()).isEqualTo(Instant.ofEpochSecond(222));
    }

    private void putWatermark(final KeyValueStore keyValueStore, final Instant instant) {
        keyValueStore.put("watermark", String.valueOf(instant.toEpochMilli()));
    }

    private static class MutableClock extends Clock {

        private Instant currentInstant;

        private MutableClock(final Instant initialInstant) {
            this.currentInstant = initialInstant;
        }

        private void advance(final Duration duration) {
            currentInstant = currentInstant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return Clock.systemUTC().getZone();
        }

        @Override
        public Clock withZone(final ZoneId zone) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Instant instant() {
            return currentInstant;
        }

    }

}