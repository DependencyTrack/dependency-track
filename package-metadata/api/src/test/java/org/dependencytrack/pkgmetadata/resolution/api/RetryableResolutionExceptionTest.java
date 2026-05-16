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
package org.dependencytrack.pkgmetadata.resolution.api;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class RetryableResolutionExceptionTest {

    private static final Instant FIXED_NOW = Instant.parse("2024-01-01T00:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);

    @ParameterizedTest
    @ValueSource(longs = {-1, 0})
    void shouldRejectNonPositiveRetryAfter(long seconds) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new RetryableResolutionException(
                        null, null, Duration.of(seconds, ChronoUnit.SECONDS)));
    }

    @Test
    void shouldParseRetryAfterAsDelaySeconds() {
        assertThat(RetryableResolutionException.tryParseRetryAfterHeader("60", FIXED_CLOCK))
                .isEqualTo(Duration.ofSeconds(60));
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "-5", "not-a-date"})
    void shouldReturnNullForUnusableHeaderValue(String value) {
        assertThat(RetryableResolutionException.tryParseRetryAfterHeader(value, FIXED_CLOCK)).isNull();
    }

    @Test
    void shouldParseRetryAfterAsHttpDate() {
        final Instant deadline = FIXED_NOW.plus(Duration.ofMinutes(10));
        final String httpDate = DateTimeFormatter.RFC_1123_DATE_TIME
                .format(deadline.atZone(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS));

        assertThat(RetryableResolutionException.tryParseRetryAfterHeader(httpDate, FIXED_CLOCK))
                .isEqualTo(Duration.ofMinutes(10));
    }

    @Test
    void shouldReturnNullWhenHttpDateIsInPast() {
        final String httpDate = DateTimeFormatter.RFC_1123_DATE_TIME
                .format(FIXED_NOW.minus(Duration.ofMinutes(5)).atZone(ZoneOffset.UTC));

        assertThat(RetryableResolutionException.tryParseRetryAfterHeader(httpDate, FIXED_CLOCK)).isNull();
    }

}