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
package org.dependencytrack.support.net;

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

class HttpRetryTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @ParameterizedTest
    @ValueSource(ints = {429, 502, 503, 504})
    void shouldClassifyRetryableStatusCodes(int statusCode) {
        assertThat(new HttpRetry(statusCode, null, "description").isRetryable()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 400, 401, 402, 403, 404, 500, 501})
    void shouldNotClassifyNonRetryableStatusCodes(int statusCode) {
        assertThat(new HttpRetry(statusCode, null, "description").isRetryable()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void shouldRejectNonPositiveRetryAfter(long seconds) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new HttpRetry(429, Duration.ofSeconds(seconds), "description"));
    }

    @Test
    void shouldParseRetryAfterAsDelaySeconds() {
        assertThat(HttpRetry.parseRetryAfterHeader("60", CLOCK))
                .isEqualTo(Duration.ofSeconds(60));
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "-5", "not-a-date"})
    void shouldReturnNullForUnusableHeaderValue(String value) {
        assertThat(HttpRetry.parseRetryAfterHeader(value, CLOCK)).isNull();
    }

    @Test
    void shouldParseRetryAfterAsHttpDate() {
        final Instant deadline = NOW.plus(Duration.ofMinutes(10));
        final String httpDate = DateTimeFormatter.RFC_1123_DATE_TIME
                .format(deadline.atZone(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS));

        assertThat(HttpRetry.parseRetryAfterHeader(httpDate, CLOCK))
                .isEqualTo(Duration.ofMinutes(10));
    }

    @Test
    void shouldReturnNullWhenHttpDateIsInPast() {
        final String httpDate = DateTimeFormatter.RFC_1123_DATE_TIME
                .format(NOW.minus(Duration.ofMinutes(5)).atZone(ZoneOffset.UTC));

        assertThat(HttpRetry.parseRetryAfterHeader(httpDate, CLOCK)).isNull();
    }

}
