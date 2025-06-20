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
package org.dependencytrack.util;

import alpine.Config;
import alpine.common.logging.Logger;
import io.github.resilience4j.core.EventConsumer;
import io.github.resilience4j.core.IntervalFunction;
import io.github.resilience4j.retry.event.RetryEvent;
import io.github.resilience4j.retry.event.RetryOnErrorEvent;
import io.github.resilience4j.retry.event.RetryOnIgnoredErrorEvent;
import io.github.resilience4j.retry.event.RetryOnRetryEvent;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.conn.ConnectTimeoutException;
import org.dependencytrack.common.ConfigKey;

import java.io.Closeable;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.Predicate;

/**
 * @since 4.11.0
 */
public class RetryUtil {

    private static final Set<Class<? extends Throwable>> KNOWN_TRANSIENT_EXCEPTIONS = Set.of(
            ConnectTimeoutException.class,
            SocketTimeoutException.class,
            TimeoutException.class
    );
    private static final Set<Integer> KNOWN_TRANSIENT_STATUS_CODES = Set.of(
            HttpStatus.SC_TOO_MANY_REQUESTS,
            HttpStatus.SC_BAD_GATEWAY,
            HttpStatus.SC_SERVICE_UNAVAILABLE,
            HttpStatus.SC_GATEWAY_TIMEOUT
    );

    public static IntervalFunction withExponentialBackoff(final ConfigKey initialDurationConfigKey,
                                                          final ConfigKey multiplierConfigKey,
                                                          final ConfigKey maxDurationConfigKey) {
        return IntervalFunction.ofExponentialBackoff(
                Duration.ofMillis(Config.getInstance().getPropertyAsInt(initialDurationConfigKey)),
                Config.getInstance().getPropertyAsInt(multiplierConfigKey),
                Duration.ofMillis(Config.getInstance().getPropertyAsInt(maxDurationConfigKey))
        );
    }

    public static <T extends RetryEvent> EventConsumer<T> logRetryEventWith(final Logger logger) {
        return event -> {
            if (event instanceof final RetryOnRetryEvent retryEvent) {
                final var message = "Encountered retryable error for %s; Will execute retry #%d in %s"
                        .formatted(event.getName(), event.getNumberOfRetryAttempts(), retryEvent.getWaitInterval());
                if (event.getLastThrowable() != null) {
                    logger.warn(message, event.getLastThrowable());
                } else {
                    logger.warn(message);
                }
            } else if (event instanceof final RetryOnErrorEvent errorEvent) {
                final var message = "Max retry attempts exceeded for %s after %d attempts"
                        .formatted(errorEvent.getName(), errorEvent.getNumberOfRetryAttempts());
                if (errorEvent.getLastThrowable() != null) {
                    logger.error(message, errorEvent.getLastThrowable());
                } else {
                    logger.error(message);
                }
            } else if (event instanceof final RetryOnIgnoredErrorEvent ignoredErrorEvent) {
                if (!logger.isDebugEnabled()) {
                    return;
                }

                final var message = "Ignored error for %s after %d attempts; Will not retry"
                        .formatted(event.getName(), event.getNumberOfRetryAttempts());
                if (event.getLastThrowable() != null) {
                    logger.debug(message, event.getLastThrowable());
                } else {
                    logger.debug(message);
                }
            }
        };
    }

    public static <T extends Closeable> BiConsumer<Integer, T> maybeClosePreviousResult() {
        return (attempt, closeable) -> {
            if (closeable != null) {
                try {
                    closeable.close();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    public static Predicate<CloseableHttpResponse> withTransientErrorCode() {
        return response -> response != null
                           && response.getStatusLine() != null
                           && KNOWN_TRANSIENT_STATUS_CODES.contains(response.getStatusLine().getStatusCode());
    }

    public static Predicate<Throwable> withTransientCause() {
        return withCauseAnyOf(KNOWN_TRANSIENT_EXCEPTIONS);
    }

    public static Predicate<Throwable> withCauseAnyOf(final Collection<Class<? extends Throwable>> causeClasses) {
        return throwable -> {
            for (final Throwable cause : ExceptionUtils.getThrowableList(throwable)) {
                final boolean isMatch = causeClasses.stream()
                        .anyMatch(causeClass -> causeClass.isAssignableFrom(cause.getClass()));
                if (isMatch) {
                    return true;
                }
            }

            return false;
        };
    }

}
