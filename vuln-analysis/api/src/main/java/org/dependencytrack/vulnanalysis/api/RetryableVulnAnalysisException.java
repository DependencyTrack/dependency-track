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
package org.dependencytrack.vulnanalysis.api;

import org.dependencytrack.support.net.HttpRetry;
import org.dependencytrack.support.net.TransientNetworkErrors;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.time.Duration;

/// Exception for vulnerability analysis failures that may be retried.
///
/// @since 5.1.0
public class RetryableVulnAnalysisException extends RuntimeException {

    private final @Nullable Duration retryAfter;

    public RetryableVulnAnalysisException(
            @Nullable String message,
            @Nullable Throwable cause,
            @Nullable Duration retryAfter) {
        super(message, cause);
        if (retryAfter != null && (retryAfter.isZero() || retryAfter.isNegative())) {
            throw new IllegalArgumentException("retryAfter must be positive, but was: " + retryAfter);
        }
        this.retryAfter = retryAfter;
    }

    public RetryableVulnAnalysisException(@Nullable String message, @Nullable Throwable cause) {
        this(message, cause, null);
    }

    public @Nullable Duration retryAfter() {
        return retryAfter;
    }

    public static void throwIfRetryableHttpError(HttpResponse<?> response) {
        final HttpRetry retry = HttpRetry.of(response);
        if (!retry.isRetryable()) {
            return;
        }

        throw new RetryableVulnAnalysisException(retry.description(), null, retry.retryAfter());
    }

    public static void throwIfRetryableNetworkError(IOException e, @Nullable String message) {
        if (TransientNetworkErrors.isTransient(e)) {
            throw new RetryableVulnAnalysisException(message, e);
        }
    }

}
