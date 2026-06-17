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
package org.dependencytrack.dex.engine.support;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CircuitBreakerStateTransitionLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(CircuitBreakerStateTransitionLogger.class);

    private CircuitBreakerStateTransitionLogger() {
    }

    public static void attach(CircuitBreakerRegistry registry) {
        registry.getEventPublisher().onEntryAdded(
                entryEvent -> onBreakerAdded(entryEvent.getAddedEntry()));
        registry.getEventPublisher().onEntryReplaced(
                entryEvent -> onBreakerAdded(entryEvent.getNewEntry()));
    }

    private static void onBreakerAdded(CircuitBreaker breaker) {
        breaker.getEventPublisher().onStateTransition(transitionEvent -> {
            final CircuitBreaker.Metrics metrics = breaker.getMetrics();
            switch (transitionEvent.getStateTransition().getToState()) {
                case OPEN -> LOGGER.warn(
                        "Circuit breaker {} opened (failureRate={}%, slowCallRate={}%, calls={})",
                        breaker.getName(),
                        metrics.getFailureRate(),
                        metrics.getSlowCallRate(),
                        metrics.getNumberOfBufferedCalls());
                case HALF_OPEN -> LOGGER.info(
                        "Circuit breaker {} is half-open; probing recovery",
                        breaker.getName());
                case CLOSED -> LOGGER.info(
                        "Circuit breaker {} closed; downstream healthy",
                        breaker.getName());
                default -> {
                }
            }
        });
    }

}
