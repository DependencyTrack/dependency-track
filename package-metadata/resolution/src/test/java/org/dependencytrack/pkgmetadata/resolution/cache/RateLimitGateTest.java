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
package org.dependencytrack.pkgmetadata.resolution.cache;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitGateTest {

    private static final URI URI_A = URI.create("https://repo.example.com/path");
    private static final URI URI_B = URI.create("https://other.example.com/path");

    @Test
    void shouldReturnNullWhenHostWasNeverRecorded() {
        final var gate = new RateLimitGate(new MutableClock());

        assertThat(gate.checkRateLimited(URI_A)).isNull();
    }

    @ParameterizedTest
    @MethodSource
    void shouldGateForBackoffDerivedFromRetryAfter(Duration retryAfter, Duration expectedBackoff) {
        final var clock = new MutableClock();
        final var gate = new RateLimitGate(clock);

        gate.recordRateLimit(URI_A, retryAfter);
        assertThat(gate.checkRateLimited(URI_A))
                .isEqualTo(clock.instant().plus(expectedBackoff));
    }

    static Stream<Arguments> shouldGateForBackoffDerivedFromRetryAfter() {
        return Stream.of(
                Arguments.of(null, Duration.ofSeconds(30)),
                Arguments.of(Duration.ofSeconds(45), Duration.ofSeconds(45)),
                Arguments.of(Duration.ofHours(1), Duration.ofMinutes(5)));
    }

    @Test
    void shouldClearEntryAfterWindowElapses() {
        final var clock = new MutableClock();
        final var gate = new RateLimitGate(clock);

        gate.recordRateLimit(URI_A, Duration.ofSeconds(30));
        clock.advance(Duration.ofSeconds(31));

        assertThat(gate.checkRateLimited(URI_A)).isNull();

        gate.recordRateLimit(URI_A, Duration.ofSeconds(10));
        assertThat(gate.checkRateLimited(URI_A))
                .isEqualTo(clock.instant().plusSeconds(10));
    }

    @Test
    void shouldKeepLaterExpiryWhenRecordedTwice() {
        final var clock = new MutableClock();
        final var gate = new RateLimitGate(clock);

        gate.recordRateLimit(URI_A, Duration.ofSeconds(120));
        final Instant longerWindow = gate.checkRateLimited(URI_A);

        gate.recordRateLimit(URI_A, Duration.ofSeconds(10));
        assertThat(gate.checkRateLimited(URI_A)).isEqualTo(longerWindow);
    }

    @Test
    void shouldExtendWindowWhenSecondSignalIsLater() {
        final var clock = new MutableClock();
        final var gate = new RateLimitGate(clock);

        gate.recordRateLimit(URI_A, Duration.ofSeconds(30));
        clock.advance(Duration.ofSeconds(10));
        gate.recordRateLimit(URI_A, Duration.ofSeconds(60));

        assertThat(gate.checkRateLimited(URI_A))
                .isEqualTo(clock.instant().plusSeconds(60));
    }

    @Test
    void shouldGateHostsIndependently() {
        final var clock = new MutableClock();
        final var gate = new RateLimitGate(clock);

        gate.recordRateLimit(URI_A, Duration.ofSeconds(60));

        assertThat(gate.checkRateLimited(URI_A)).isNotNull();
        assertThat(gate.checkRateLimited(URI_B)).isNull();
    }

    @Test
    void shouldIgnoreRecordWhenAuthorityIsNull() {
        final var gate = new RateLimitGate(new MutableClock());
        final URI relative = URI.create("/path-only");
        assertThat(relative.getAuthority()).isNull();

        gate.recordRateLimit(relative, Duration.ofSeconds(60));
        assertThat(gate.checkRateLimited(relative)).isNull();
    }

    private static final class MutableClock extends Clock {

        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2024-01-01T00:00:00Z"));

        @Override
        public Instant instant() {
            return now.get();
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            throw new UnsupportedOperationException();
        }

        void advance(Duration delta) {
            now.updateAndGet(current -> current.plus(delta));
        }

    }

}
