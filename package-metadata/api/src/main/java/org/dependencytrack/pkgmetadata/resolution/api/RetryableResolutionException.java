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

import org.jspecify.annotations.Nullable;

import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * Exception for resolution failures that may be retried.
 *
 * @since 5.0.0
 */
public class RetryableResolutionException extends RuntimeException {

    private final @Nullable Duration retryAfter;

    public RetryableResolutionException(
            @Nullable String message,
            @Nullable Throwable cause,
            @Nullable Duration retryAfter) {
        super(message, cause);
        if (retryAfter != null && (retryAfter.isZero() || retryAfter.isNegative())) {
            throw new IllegalArgumentException("retryAfter must be positive, but was: " + retryAfter);
        }
        this.retryAfter = retryAfter;
    }

    public RetryableResolutionException(@Nullable String message, @Nullable Throwable cause) {
        this(message, cause, null);
    }

    public RetryableResolutionException(@Nullable Throwable cause) {
        this(null, cause, null);
    }

    public RetryableResolutionException(@Nullable String message) {
        this(message, null, null);
    }

    public @Nullable Duration retryAfter() {
        return retryAfter;
    }

    public static void throwIfRetryableError(HttpResponse<?> response, Clock clock) {
        final int statusCode = response.statusCode();

        if (statusCode == 429) {
            throw new RetryableResolutionException(
                    "Rate limited by %s".formatted(response.request().uri()),
                    null,
                    extractRetryAfter(response, clock));
        }

        if (statusCode == 503 || statusCode == 504) {
            throw new RetryableResolutionException(
                    "Server error %d from %s".formatted(statusCode, response.request().uri()),
                    null,
                    extractRetryAfter(response, clock));
        }
    }

    private static @Nullable Duration extractRetryAfter(HttpResponse<?> response, Clock clock) {
        return response.headers()
                .firstValue("Retry-After")
                .map(value -> tryParseRetryAfterHeader(value, clock))
                .orElse(null);
    }

    static @Nullable Duration tryParseRetryAfterHeader(String value, Clock clock) {
        final String trimmed = value.strip();
        try {
            final long seconds = Long.parseLong(trimmed);
            return seconds > 0 ? Duration.ofSeconds(seconds) : null;
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
