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

import org.jspecify.annotations.Nullable;

import java.net.URI;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

import static java.util.Objects.requireNonNull;

/// @since 5.1.0
public record HttpRetry(int statusCode, @Nullable Duration retryAfter, String description) {

    public HttpRetry {
        if (retryAfter != null && (retryAfter.isZero() || retryAfter.isNegative())) {
            throw new IllegalArgumentException("retryAfter must be positive, but was: " + retryAfter);
        }
        requireNonNull(description, "description must not be null");
    }

    public static HttpRetry of(HttpResponse<?> response) {
        return of(response, Clock.systemUTC());
    }

    public static HttpRetry of(HttpResponse<?> response, Clock clock) {
        final int statusCode = response.statusCode();
        final URI requestUri = response.request().uri();

        return new HttpRetry(
                statusCode,
                isRetryableStatus(statusCode)
                        ? extractRetryAfter(response, clock)
                        : null,
                statusCode == 429
                        ? "Rate limited by %s".formatted(requestUri)
                        : "Server error %d from %s".formatted(statusCode, requestUri));
    }

    public boolean isRetryable() {
        return isRetryableStatus(statusCode);
    }

    private static boolean isRetryableStatus(int statusCode) {
        return statusCode == 429 || statusCode == 502 || statusCode == 503 || statusCode == 504;
    }

    private static @Nullable Duration extractRetryAfter(HttpResponse<?> response, Clock clock) {
        return response.headers()
                .firstValue("Retry-After")
                .map(value -> parseRetryAfterHeader(value, clock))
                .orElse(null);
    }

    static @Nullable Duration parseRetryAfterHeader(String value, Clock clock) {
        final String trimmed = value.strip();
        try {
            final long seconds = Long.parseLong(trimmed);
            return seconds > 0
                    ? Duration.ofSeconds(seconds)
                    : null;
        } catch (NumberFormatException _) {
            // Fallthrough to date parsing.
        }

        try {
            final Instant deadline = ZonedDateTime
                    .parse(trimmed, DateTimeFormatter.RFC_1123_DATE_TIME)
                    .toInstant();
            final Duration delta = Duration.between(clock.instant(), deadline);
            return (delta.isZero() || delta.isNegative()) ? null : delta;
        } catch (DateTimeParseException _) {
            return null;
        }
    }

}
