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
import java.time.Duration;

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

    public static void throwIfRetryableError(HttpResponse<?> response) {
        final int statusCode = response.statusCode();

        if (statusCode == 429) {
            final Duration retryAfter = response.headers()
                    .firstValue("Retry-After")
                    .map(RetryableResolutionException::parseRetryAfterHeader)
                    .orElse(null);

            throw new RetryableResolutionException(
                    "Rate limited by %s".formatted(response.request().uri()), null, retryAfter);
        }

        if (statusCode == 503 || statusCode == 504) {
            throw new RetryableResolutionException(
                    "Server error %d from %s".formatted(statusCode, response.request().uri()));
        }
    }

    private static @Nullable Duration parseRetryAfterHeader(String value) {
        try {
            final long seconds = Long.parseLong(value.strip());
            return seconds > 0
                    ? Duration.ofSeconds(seconds)
                    : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

}
