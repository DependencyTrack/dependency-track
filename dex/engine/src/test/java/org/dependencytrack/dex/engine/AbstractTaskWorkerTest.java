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
package org.dependencytrack.dex.engine;

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.engine.persistence.model.PolledActivityTask;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class AbstractTaskWorkerTest {

    private MeterRegistry meterRegistry;
    private TestWorker worker;

    @BeforeEach
    void beforeEach() {
        meterRegistry = new SimpleMeterRegistry();
    }

    @AfterEach
    void afterEach() {
        if (worker != null) {
            worker.close();
        }
    }

    @Test
    void shouldExposeConcurrencyUtilizationGauge() throws Exception {
        final var processGate = new CountDownLatch(1);
        final var processStarted = new CountDownLatch(2);
        worker = new TestWorker("test", 4, meterRegistry, processGate, processStarted);
        worker.start();

        assertThat(meterRegistry.get("dt.dex.engine.task.worker.concurrency.utilization")
                .tag("workerType", "TestWorker")
                .tag("name", "test")
                .gauge().value()).isEqualTo(0.0);

        worker.queueTwoTasks();

        assertThat(processStarted.await(5, TimeUnit.SECONDS)).isTrue();

        await("Utilization climbs to 0.5")
                .atMost(Duration.ofSeconds(2))
                .untilAsserted(() -> assertThat(meterRegistry.get("dt.dex.engine.task.worker.concurrency.utilization")
                        .tag("workerType", "TestWorker")
                        .tag("name", "test")
                        .gauge().value()).isEqualTo(0.5));

        processGate.countDown();

        await("Utilization returns to 0")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(meterRegistry.get("dt.dex.engine.task.worker.concurrency.utilization")
                        .tag("workerType", "TestWorker")
                        .tag("name", "test")
                        .gauge().value()).isEqualTo(0.0));
    }

    private static final class TestWorker extends AbstractTaskWorker<ActivityTask> {

        private final CountDownLatch processGate;
        private final CountDownLatch processStarted;
        private final AtomicInteger pollsRemaining = new AtomicInteger(0);

        TestWorker(
                String name,
                int maxConcurrency,
                MeterRegistry meterRegistry,
                CountDownLatch processGate,
                CountDownLatch processStarted) {
            super(
                    name,
                    Duration.ofMillis(10),
                    IntervalFunction.of(Duration.ofMillis(10)),
                    maxConcurrency,
                    meterRegistry);
            this.processGate = processGate;
            this.processStarted = processStarted;
        }

        void queueTwoTasks() {
            pollsRemaining.set(2);
            nudge();
        }

        @Override
        List<ActivityTask> poll(final int limit) {
            final int toEmit = Math.min(limit, pollsRemaining.getAndSet(0));
            if (toEmit <= 0) {
                return List.of();
            }

            return IntStream.range(0, toEmit)
                    .mapToObj(i -> ActivityTask.of(new PolledActivityTask(
                            UUID.randomUUID(),
                            i,
                            "noop",
                            "queue",
                            0,
                            null,
                            RetryPolicy.ofDefault().toProto(),
                            1,
                            Instant.now().plusSeconds(60),
                            0)))
                    .toList();
        }

        @Override
        void process(final ActivityTask task) {
            processStarted.countDown();

            try {
                processGate.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        @Override
        void abandon(final ActivityTask task) {
        }

    }

}
