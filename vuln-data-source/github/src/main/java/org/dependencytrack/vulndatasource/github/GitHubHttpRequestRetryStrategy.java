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

import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.core5.http.ConnectionClosedException;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * @since 5.0.0
 */
final class GitHubHttpRequestRetryStrategy extends DefaultHttpRequestRetryStrategy {

    private enum RateLimitStrategy {
        RETRY_AFTER,
        LIMIT_RESET
    }

    private record RateLimitInfo(
            RateLimitStrategy strategy,
            Duration retryAfter,
            Long remainingRequests,
            Long requestLimit,
            Instant requestLimitResetAt) {

        private static RateLimitInfo of(final HttpResponse response) {
            final Header retryAfterHeader = response.getFirstHeader("retry-after");
            if (retryAfterHeader != null) {
                final long retryAfterSeconds = Long.parseLong(retryAfterHeader.getValue().trim());
                return new RateLimitInfo(RateLimitStrategy.RETRY_AFTER, Duration.ofSeconds(retryAfterSeconds), null, null, null);
            }

            final Header remainingRequestsHeader = response.getFirstHeader("x-ratelimit-remaining");
            if (remainingRequestsHeader != null) {
                final long remainingRequests = Long.parseLong(remainingRequestsHeader.getValue().trim());
                final long requestLimit = Long.parseLong(response.getFirstHeader("x-ratelimit-limit").getValue().trim());
                final long requestLimitResetEpochSeconds = Long.parseLong(response.getFirstHeader("x-ratelimit-reset").getValue().trim());
                return new RateLimitInfo(RateLimitStrategy.LIMIT_RESET, null, remainingRequests, requestLimit, Instant.ofEpochSecond(requestLimitResetEpochSeconds));
            }

            return null;
        }

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(GitHubHttpRequestRetryStrategy.class);

    private final Duration maxRetryDelay = Duration.ofMinutes(3);

    GitHubHttpRequestRetryStrategy() {
        super(
                /* maxRetries */ 6,
                /* defaultRetryInterval */ TimeValue.ofSeconds(1L),
                // Same as DefaultHttpRequestRetryStrategy.
                /* retryableExceptions */ List.of(
                        ConnectException.class,
                        ConnectionClosedException.class,
                        InterruptedIOException.class,
                        NoRouteToHostException.class,
                        SSLException.class,
                        UnknownHostException.class),
                // Same as DefaultHttpRequestRetryStrategy, with addition of 403,
                // since GitHub might use that status to indicate rate limiting.
                /* retryableCodes */ List.of(403, 429, 503));
    }

    @Override
    public boolean retryRequest(final HttpResponse response, final int execCount, final HttpContext context) {
        if (response.getCode() != 403 && response.getCode() != 429) {
            return super.retryRequest(response, execCount, context);
        }

        final var rateLimitInfo = RateLimitInfo.of(response);
        if (rateLimitInfo == null) {
            if (response.getCode() == 403) {
                // Authorization failure. Do not retry.
                return false;
            }

            return super.retryRequest(response, execCount, context);
        }

        return switch (rateLimitInfo.strategy()) {
            case RETRY_AFTER -> {
                // Usually GitHub will request to wait for 1min. This may change though, and we can't risk
                // blocking a worker thread unnecessarily for a long period of time.
                if (rateLimitInfo.retryAfter().compareTo(maxRetryDelay) > 0) {
                    LOGGER.warn("""
                            Rate limiting detected; GitHub API indicates retries to be acceptable after {}, \
                            which exceeds the maximum retry duration of {}. \
                            Not performing any further retries.""",
                            rateLimitInfo.retryAfter(), maxRetryDelay);
                    yield false;
                }

                yield true;
            }
            case LIMIT_RESET -> {
                if (rateLimitInfo.remainingRequests() > 0) {
                    // Still have requests budget remaining. Failure reason is not rate limiting.
                    yield super.retryRequest(response, execCount, context);
                }

                // The duration after which the limit is reset is not defined in GitHub's API docs.
                // Need to safeguard ourselves from blocking the worker thread for too long.
                final var untilResetDuration = Duration.between(Instant.now(), rateLimitInfo.requestLimitResetAt());
                if (untilResetDuration.compareTo(maxRetryDelay) > 0) {
                    LOGGER.warn("""
                            Primary rate limit of {} requests exhausted. The rate limit will reset at {} (in {}), \
                            which exceeds the maximum retry duration of {}. Not performing any further retries.""",
                            rateLimitInfo.requestLimit(), rateLimitInfo.requestLimitResetAt(), untilResetDuration, maxRetryDelay);
                    yield false;
                }

                yield true;
            }
        };
    }

    @Override
    public TimeValue getRetryInterval(final HttpResponse response, final int execCount, final HttpContext context) {
        // When this is called, retryRequest was already invoked to determine whether
        // a retry should be performed. So we can skip the status code check here.

        final var rateLimitInfo = RateLimitInfo.of(response);
        if (rateLimitInfo == null) {
            return super.getRetryInterval(response, execCount, context);
        }

        return switch (rateLimitInfo.strategy()) {
            case RETRY_AFTER -> {
                LOGGER.warn("""
                        Rate limiting detected; GitHub indicates retries to be acceptable after {}; \
                        Will wait and try again.""", rateLimitInfo.retryAfter());
                yield TimeValue.ofMilliseconds(rateLimitInfo.retryAfter().toMillis());
            }
            case LIMIT_RESET -> {
                final var retryAfter = Duration.between(Instant.now(), rateLimitInfo.requestLimitResetAt());
                LOGGER.warn("""
                        Primary rate limit of {} requests exhausted. Limit will reset at {}; \
                        Will wait for {} and try again.""",
                        rateLimitInfo.requestLimit(), rateLimitInfo.requestLimitResetAt(), retryAfter);
                yield TimeValue.ofMilliseconds(retryAfter.toMillis());
            }
        };
    }

}
