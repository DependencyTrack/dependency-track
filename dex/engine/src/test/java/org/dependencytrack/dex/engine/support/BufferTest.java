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

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.awaitility.Awaitility.await;

class BufferTest {

    @Test
    void shouldFlushAtInterval() throws Exception {
        final var flushedItems = new ArrayList<String>();

        final var buffer = new Buffer<@NonNull String>(
                "test",
                flushedItems::addAll,
                Duration.ofMillis(10),
                /* maxBatchSize */ 10,
                new SimpleMeterRegistry(),
                CircuitBreakerRegistry.ofDefaults());

        try (buffer) {
            buffer.start();

            final CompletableFuture<Void> future = buffer.add("foo");
            future.get(100, TimeUnit.MILLISECONDS);

            assertThat(flushedItems).containsOnly("foo");
        }
    }

    @Test
    void addShouldThrowWhenNotRunning() {
        final Consumer<List<String>> batchConsumer = ignored -> {
        };

        final var buffer = new Buffer<>(
                "test",
                batchConsumer,
                Duration.ZERO,
                /* maxBatchSize */ 10,
                new SimpleMeterRegistry(),
                CircuitBreakerRegistry.ofDefaults());

        try (buffer) {
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> buffer.add("foo").get(100, TimeUnit.MILLISECONDS))
                    .withMessage("Cannot accept new items in current status: CREATED");
        }
    }

    @Test
    void addShouldFlushWhenMaxBatchSizeIsReached() throws Exception {
        final var flushedBatches = new ArrayBlockingQueue<List<String>>(5);

        final var buffer = new Buffer<>(
                "test",
                flushedBatches::add,
                Duration.ofMillis(50),
                /* maxBatchSize */ 2,
                Duration.ofSeconds(5),
                new SimpleMeterRegistry(),
                CircuitBreakerRegistry.ofDefaults());

        try (buffer) {
            buffer.start();

            buffer.add("foo");
            buffer.add("bar").get(100, TimeUnit.MILLISECONDS);

            assertThat(flushedBatches).containsExactly(List.of("foo", "bar"));
        }
    }

    @Test
    void shouldOpenCircuitBreakerAfterRepeatedFailures() throws Exception {
        final var flushAttempts = new AtomicInteger();
        final Consumer<List<String>> batchConsumer = batch -> {
            flushAttempts.incrementAndGet();
            throw new RuntimeException("downstream broken");
        };

        final var registry = CircuitBreakerRegistry.of(
                CircuitBreakerConfig.custom()
                        .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                        .slidingWindowSize(3)
                        .minimumNumberOfCalls(3)
                        .failureRateThreshold(50.0f)
                        .waitDurationInOpenState(Duration.ofMinutes(1))
                        .build());

        final var buffer = new Buffer<>(
                "test",
                batchConsumer,
                Duration.ofMillis(10),
                /* maxBatchSize */ 1,
                Duration.ofMillis(100),
                new SimpleMeterRegistry(),
                registry);

        try (buffer) {
            buffer.start();

            for (int i = 0; i < 3; i++) {
                final CompletableFuture<Void> future = buffer.add("item-" + i);
                assertThatExceptionOfType(ExecutionException.class)
                        .isThrownBy(() -> future.get(500, TimeUnit.MILLISECONDS));
            }

            await().atMost(Duration.ofSeconds(1)).until(() -> !buffer.acceptsWork());

            final int attemptsWhenOpened = flushAttempts.get();
            await("No further flush attempts while breaker is open")
                    .during(Duration.ofMillis(200))
                    .atMost(Duration.ofMillis(500))
                    .untilAsserted(() -> assertThat(flushAttempts.get()).isEqualTo(attemptsWhenOpened));
        }
    }

    @Test
    void shouldRecoverFromOpenStateOnSuccessfulProbe() throws Exception {
        final var shouldFail = new java.util.concurrent.atomic.AtomicBoolean(true);
        final var flushedBatches = new ArrayBlockingQueue<List<String>>(10);
        final Consumer<List<String>> batchConsumer = batch -> {
            if (shouldFail.get()) {
                throw new RuntimeException("downstream broken");
            }
            flushedBatches.add(List.copyOf(batch));
        };

        final var registry = CircuitBreakerRegistry.of(
                CircuitBreakerConfig.custom()
                        .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                        .slidingWindowSize(2)
                        .minimumNumberOfCalls(2)
                        .failureRateThreshold(50.0f)
                        .waitDurationInOpenState(Duration.ofMillis(200))
                        .permittedNumberOfCallsInHalfOpenState(1)
                        .build());

        final var buffer = new Buffer<>(
                "test",
                batchConsumer,
                Duration.ofMillis(20),
                /* maxBatchSize */ 1,
                Duration.ofMillis(100),
                new SimpleMeterRegistry(),
                registry);

        try (buffer) {
            buffer.start();

            for (int i = 0; i < 2; i++) {
                final CompletableFuture<Void> future = buffer.add("fail-" + i);
                assertThatExceptionOfType(ExecutionException.class)
                        .isThrownBy(() -> future.get(500, TimeUnit.MILLISECONDS));
            }

            await().atMost(Duration.ofSeconds(1)).until(() -> !buffer.acceptsWork());

            shouldFail.set(false);

            await().atMost(Duration.ofSeconds(5))
                    .pollInterval(Duration.ofMillis(50))
                    .until(() -> {
                        try {
                            buffer.add("recovery").get(200, TimeUnit.MILLISECONDS);
                            return true;
                        } catch (Exception e) {
                            return false;
                        }
                    });

            assertThat(flushedBatches).contains(List.of("recovery"));
            assertThat(buffer.acceptsWork()).isTrue();
        }
    }

    @Test
    void addShouldFailFastWhileBreakerIsOpen() throws Exception {
        final Consumer<List<String>> batchConsumer = batch -> {
            throw new RuntimeException("downstream broken");
        };

        final var registry = CircuitBreakerRegistry.of(
                CircuitBreakerConfig.custom()
                        .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                        .slidingWindowSize(2)
                        .minimumNumberOfCalls(2)
                        .failureRateThreshold(50.0f)
                        .waitDurationInOpenState(Duration.ofMinutes(1))
                        .build());

        final var buffer = new Buffer<>(
                "test",
                batchConsumer,
                Duration.ofMillis(10),
                /* maxBatchSize */ 1,
                /* itemsQueueTimeout */ Duration.ofMillis(100),
                new SimpleMeterRegistry(),
                registry);

        try (buffer) {
            buffer.start();

            for (int i = 0; i < 2; i++) {
                final CompletableFuture<Void> future = buffer.add("fail-" + i);
                assertThatExceptionOfType(ExecutionException.class)
                        .isThrownBy(() -> future.get(500, TimeUnit.MILLISECONDS));
            }

            await().atMost(Duration.ofSeconds(1)).until(() -> !buffer.acceptsWork());

            final CompletableFuture<Void> future = buffer.add("rejected");
            assertThatExceptionOfType(ExecutionException.class)
                    .isThrownBy(() -> future.get(500, TimeUnit.MILLISECONDS))
                    .withCauseInstanceOf(CallNotPermittedException.class);
        }
    }

}
