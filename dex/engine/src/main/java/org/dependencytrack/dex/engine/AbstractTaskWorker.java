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
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

abstract class AbstractTaskWorker<T extends Task> implements TaskWorker {

    private final String name;
    private final long minPollIntervalMillis;
    private final IntervalFunction pollBackoffFunction;
    private final int maxConcurrency;
    private final Semaphore semaphore;
    private final MeterRegistry meterRegistry;
    private final BooleanSupplier downstreamAcceptsWork;
    private final Lock statusLock;
    final Logger logger;

    private volatile Status status = Status.CREATED;
    private volatile boolean nudged = false;
    private @Nullable Thread pollThread;
    private @Nullable ExecutorService taskExecutor;
    private @Nullable Timer pollLatencyTimer;
    private @Nullable Counter pollsCounter;
    private @Nullable Counter backpressureSkipsCounter;
    private @Nullable MeterProvider<DistributionSummary> polledTasksDistribution;
    private @Nullable MeterProvider<Counter> processedCounter;
    private @Nullable MeterProvider<Timer> processLatencyTimer;

    AbstractTaskWorker(
            final String name,
            final Duration minPollInterval,
            final IntervalFunction pollBackoffFunction,
            final int maxConcurrency,
            final MeterRegistry meterRegistry,
            final BooleanSupplier downstreamAcceptsWork) {
        this.name = name;
        this.minPollIntervalMillis = requireNonNull(minPollInterval, "minPollInterval must not be null").toMillis();
        this.pollBackoffFunction = requireNonNull(pollBackoffFunction, "pollBackoffFunction must not be null");
        this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
        this.downstreamAcceptsWork = requireNonNull(downstreamAcceptsWork, "downstreamAcceptsWork must not be null");
        this.statusLock = new ReentrantLock();
        this.maxConcurrency = maxConcurrency;
        this.semaphore = new Semaphore(maxConcurrency);
        this.logger = LoggerFactory.getLogger(getClass());
    }

    abstract List<T> poll(int limit);

    abstract void process(T task);

    abstract void abandon(T task);

    @Override
    public void start() {
        setStatus(Status.STARTING);

        pollThread = Thread.ofPlatform()
                .name("%s-Poller-".formatted(getClass().getSimpleName()), 0)
                .unstarted(this::pollAndDispatch);

        final var taskExecutorName = "%s-%s-Executor".formatted(getClass().getSimpleName(), name);
        taskExecutor = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .name(taskExecutorName + "-", 0)
                        .factory());

        new ExecutorServiceMetrics(taskExecutor, taskExecutorName, null).bindTo(meterRegistry);

        final var commonMeterTags = List.of(Tag.of("workerType", getClass().getSimpleName()));
        pollLatencyTimer = Timer
                .builder("dt.dex.engine.task.worker.poll.latency")
                .tags(commonMeterTags)
                .register(meterRegistry);
        pollsCounter = Counter
                .builder("dt.dex.engine.task.worker.polls")
                .tags(commonMeterTags)
                .register(meterRegistry);
        backpressureSkipsCounter = Counter
                .builder("dt.dex.engine.task.worker.poll.skipped.backpressure")
                .tags(commonMeterTags)
                .register(meterRegistry);
        polledTasksDistribution = DistributionSummary
                .builder("dt.dex.engine.task.worker.tasks.polled")
                .tags(commonMeterTags)
                .withRegistry(meterRegistry);
        processedCounter = Counter
                .builder("dt.dex.engine.task.worker.tasks.processed")
                .tags(commonMeterTags)
                .withRegistry(meterRegistry);
        processLatencyTimer = Timer
                .builder("dt.dex.engine.task.worker.process.latency")
                .tags(commonMeterTags)
                .withRegistry(meterRegistry);
        Gauge
                .builder(
                        "dt.dex.engine.task.worker.concurrency.utilization",
                        this,
                        worker -> 1.0 - ((double) worker.semaphore.availablePermits() / worker.maxConcurrency))
                .description("Fraction (0-1) of the worker's concurrency slots currently in use")
                .tags(commonMeterTags)
                .tag("name", name)
                .register(meterRegistry);

        pollThread.start();

        setStatus(Status.RUNNING);
    }

    @Override
    public Status status() {
        return status;
    }

    @Override
    public void close() {
        setStatus(Status.STOPPING);

        if (pollThread != null && pollThread.isAlive()) {
            LockSupport.unpark(pollThread);
            logger.debug("Waiting for poll thread to stop");
            try {
                final boolean terminated = pollThread.join(Duration.ofSeconds(10));
                if (!terminated) {
                    logger.warn("Poll thread did not stop in time; Interrupting it");
                    pollThread.interrupt();
                }
            } catch (InterruptedException e) {
                logger.warn("Interrupted waiting for poll thread to stop", e);
                Thread.currentThread().interrupt();
                pollThread.interrupt();
            }
        }
        if (taskExecutor != null) {
            logger.debug("Waiting for task executor to stop");
            taskExecutor.shutdown();

            try {
                final boolean terminated = taskExecutor.awaitTermination(30, TimeUnit.SECONDS);
                if (!terminated) {
                    logger.warn("Task executor did not stop in time; Interrupting it");
                    taskExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                logger.warn("Interrupted while waiting for task executor to stop", e);
                Thread.currentThread().interrupt();
                taskExecutor.shutdownNow();
            }
        }


        setStatus(Status.STOPPED);
    }

    @Override
    public void nudge() {
        nudged = true;
        if (pollThread != null) {
            LockSupport.unpark(pollThread);
        }
    }

    private void pollAndDispatch() {
        long nowMillis;
        long lastPolledAtMillis = 0;
        long nextPollAtMillis;
        long nextPollDueInMillis;
        int pollsWithoutResults = 0;
        int consecutiveErrors = 0;
        int consecutiveBackpressureSkips = 0;

        while (!status.isStoppingOrStopped() && !Thread.currentThread().isInterrupted()) {
            try {
                if (nudged) {
                    nudged = false;
                    pollsWithoutResults = 0;
                }

                // Start backing off after 2 poll attempts that did not yield any results,
                // OR if errors occurred previously, OR if downstream is unhealthy. It doesn't
                // make sense to keep polling at high frequency if the system sits idle, is
                // experiencing issues, or cannot process results.
                if (pollsWithoutResults < 3 && consecutiveErrors == 0 && consecutiveBackpressureSkips == 0) {
                    nowMillis = System.currentTimeMillis();
                    nextPollAtMillis = lastPolledAtMillis + minPollIntervalMillis;
                    nextPollDueInMillis = nextPollAtMillis > nowMillis
                            ? nextPollAtMillis - nowMillis
                            : 0;
                } else {
                    final int backoffAttempts = Math.max(
                            Math.max(pollsWithoutResults - 2, consecutiveErrors),
                            consecutiveBackpressureSkips);
                    nextPollDueInMillis = Math.max(
                            pollBackoffFunction.apply(backoffAttempts),
                            minPollIntervalMillis);
                }

                if (nextPollDueInMillis > 0) {
                    logger.debug("Waiting for next poll to be due in {}ms", nextPollDueInMillis);
                    LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(nextPollDueInMillis));
                    if (Thread.currentThread().isInterrupted() || status.isStoppingOrStopped()) {
                        break;
                    }

                    // Enforce minimum poll interval even when nudged.
                    final long elapsedSinceLastPoll = System.currentTimeMillis() - lastPolledAtMillis;
                    if (elapsedSinceLastPoll < minPollIntervalMillis) {
                        continue;
                    }
                }

                logger.debug("Waiting for at least one executor to be available");
                try {
                    final boolean acquired = semaphore.tryAcquire(100, TimeUnit.MILLISECONDS);
                    if (!acquired) {
                        logger.debug("All task executors busy, nothing to poll");
                        continue;
                    }

                    semaphore.release();
                } catch (InterruptedException e) {
                    logger.debug("Interrupted while waiting for available task executors", e);
                    Thread.currentThread().interrupt();
                    break;
                }

                final int tasksToPoll = semaphore.availablePermits();
                if (tasksToPoll == 0) {
                    // VERY unlikely to happen.
                    logger.warn("Semaphore permits exhausted between check and poll");
                    continue;
                }

                if (!downstreamAcceptsWork.getAsBoolean()) {
                    logger.debug("Skipping poll: downstream is not accepting work");
                    backpressureSkipsCounter.increment();
                    consecutiveBackpressureSkips++;
                    lastPolledAtMillis = System.currentTimeMillis();
                    continue;
                }

                logger.debug("Polling for up to {} tasks", tasksToPoll);
                lastPolledAtMillis = System.currentTimeMillis();
                pollsCounter.increment();

                final List<T> polledTasks;
                final Timer.Sample pollLatencySample = Timer.start();
                try {
                    polledTasks = poll(tasksToPoll);
                } finally {
                    pollLatencySample.stop(pollLatencyTimer);
                }

                consecutiveBackpressureSkips = 0;

                if (polledTasks.isEmpty()) {
                    pollsWithoutResults++;
                    consecutiveErrors = 0;
                    continue;
                }

                pollsWithoutResults = 0;
                consecutiveErrors = 0;

                final Map<Set<Tag>, Long> taskCountByMeterTags =
                        polledTasks.stream().collect(
                                Collectors.groupingBy(
                                        this::meterTags,
                                        Collectors.counting()));
                for (final Map.Entry<Set<Tag>, Long> entry : taskCountByMeterTags.entrySet()) {
                    polledTasksDistribution
                            .withTags(entry.getKey())
                            .record(entry.getValue());
                }

                final var permitAcquiredLatch = new CountDownLatch(polledTasks.size());
                final var submittedFutures = new ArrayList<Future<?>>(polledTasks.size());

                for (final T polledTask : polledTasks) {
                    submittedFutures.add(
                            taskExecutor.submit(() -> {
                                try {
                                    executeTask(polledTask, permitAcquiredLatch);
                                } catch (RuntimeException e) {
                                    logger.error("Unexpected error occurred during task execution; Abandoning task", e);
                                    abandon(polledTask);
                                }
                            }));
                }

                try {
                    // Prevent race conditions where the next poll iteration acquires a semaphore
                    // permit before the task executors acquired theirs.
                    permitAcquiredLatch.await();
                } catch (InterruptedException e) {
                    logger.warn("Interrupted while waiting for task executors to start", e);
                    submittedFutures.forEach(future -> future.cancel(/* interruptIfRunning */ true));
                    Thread.currentThread().interrupt();
                }
            } catch (Throwable t) {
                consecutiveErrors++;
                consecutiveBackpressureSkips = 0;
                logger.error("Unexpected error occurred while polling for tasks (attempt {})", consecutiveErrors, t);
            }
        }
    }

    private void executeTask(final T task, final CountDownLatch permitAcquiredLatch) {
        boolean permitAcquired = false;

        try {
            semaphore.acquire();
            permitAcquired = true;
            permitAcquiredLatch.countDown();

            final Timer.Sample processLatencySample = Timer.start();
            try {
                process(task);

                processedCounter
                        .withTags()
                        .increment();
            } finally {
                processLatencySample.stop(
                        processLatencyTimer.withTags(meterTags(task)));
            }
        } catch (InterruptedException e) {
            logger.warn("Interrupted while waiting for semaphore permit", e);
            Thread.currentThread().interrupt();
        } finally {
            if (permitAcquired) {
                semaphore.release();
            } else {
                permitAcquiredLatch.countDown();
            }
        }
    }

    private void setStatus(final Status newStatus) {
        statusLock.lock();
        try {
            if (this.status == newStatus) {
                return;
            }

            if (this.status.canTransitionTo(newStatus)) {
                logger.debug("Transitioning from status {} to {}", this.status, newStatus);
                this.status = newStatus;
                return;
            }

            throw new IllegalStateException(
                    "Can not transition from status %s to %s".formatted(this.status, newStatus));
        } finally {
            statusLock.unlock();
        }
    }

    private Set<Tag> meterTags(final Task task) {
        return Set.of(
                Tag.of("taskType", task.getClass().getSimpleName()),
                Tag.of("queueName", task.queueName()));
    }

}
