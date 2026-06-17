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
package org.dependencytrack.notification.api.publishing;

import org.jspecify.annotations.Nullable;

import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Exception for publish failures that may be retried.
 *
 * @since 5.0.0
 */
public class RetryablePublishException extends RuntimeException {

    private final @Nullable Duration retryAfter;

    public RetryablePublishException(
            @Nullable String message,
            @Nullable Throwable cause,
            @Nullable Duration retryAfter) {
        super(message, cause);
        if (retryAfter != null && (retryAfter.isZero() || retryAfter.isNegative())) {
            throw new IllegalArgumentException("retryAfter must be positive, but was: " + retryAfter);
        }
        this.retryAfter = retryAfter;
    }

    public RetryablePublishException(@Nullable String message, @Nullable Throwable cause) {
        this(message, cause, null);
    }

    public RetryablePublishException(@Nullable String message, @Nullable Duration retryAfter) {
        this(message, null, retryAfter);
    }

    public RetryablePublishException(@Nullable String message) {
        this(message, null, null);
    }

    public @Nullable Duration getRetryAfter() {
        return retryAfter;
    }

    public static void throwIfRetryableError(HttpResponse<?> response) {
        final int statusCode = response.statusCode();
        if (statusCode != 429 && statusCode != 503) {
            return;
        }

        final Duration retryAfter = response.headers()
                .firstValue("Retry-After")
                .map(RetryablePublishException::parseRetryAfterHeader)
                .orElse(null);

        throw new RetryablePublishException(
                "Request failed with retryable response code: " + statusCode, null, retryAfter);
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
