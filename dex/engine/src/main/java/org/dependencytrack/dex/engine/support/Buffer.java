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
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static io.github.resilience4j.circuitbreaker.CallNotPermittedException.createCallNotPermittedException;

public final class Buffer<T> implements Closeable {

    public enum Status {

        CREATED(1, 3), // 0
        STARTING(2),   // 1
        RUNNING(3),    // 2
        STOPPING(4),   // 3
        STOPPED;       // 4

        private final Set<Integer> allowedTransitions;

        Status(final Integer... allowedTransitions) {
            this.allowedTransitions = Set.of(allowedTransitions);
        }

        private boolean canTransitionTo(final Status newStatus) {
            return allowedTransitions.contains(newStatus.ordinal());
        }

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(Buffer.class);

    private record BufferedItem<I>(
            I item,
            long addedAtNanos,
            CompletableFuture<@Nullable Void> future) {
    }

    private final String name;
    private final Consumer<List<T>> batchConsumer;
    private final int maxBatchSize;
    private final BlockingQueue<BufferedItem<T>> itemsQueue;
    private final Duration itemsQueueTimeout;
    private final List<BufferedItem<T>> currentBatch;
    private final Thread flushThread;
    private final BlockingQueue<Boolean> flushRequestQueue;
    private final Duration flushInterval;
    private final ReentrantLock flushLock;
    private final ReentrantLock statusLock;
    private final MeterRegistry meterRegistry;
    private final CircuitBreaker circuitBreaker;
    private volatile Status status = Status.CREATED;
    private @Nullable DistributionSummary batchSizeDistribution;
    private @Nullable Timer itemWaitLatencyTimer;
    private @Nullable Counter flushCounter;
    private @Nullable Timer flushLatencyTimer;

    public Buffer(
            String name,
            Consumer<List<T>> batchConsumer,
            Duration flushInterval,
            int maxBatchSize,
            MeterRegistry meterRegistry,
            CircuitBreakerRegistry circuitBreakerRegistry) {
        this(name, batchConsumer, flushInterval, maxBatchSize, Duration.ofSeconds(5),
                meterRegistry, circuitBreakerRegistry);
    }

    Buffer(
            String name,
            Consumer<List<T>> batchConsumer,
            Duration flushInterval,
            int maxBatchSize,
            Duration itemsQueueTimeout,
            MeterRegistry meterRegistry,
            CircuitBreakerRegistry circuitBreakerRegistry) {
        this.name = name;
        this.batchConsumer = batchConsumer;
        this.maxBatchSize = maxBatchSize;
        this.itemsQueue = new ArrayBlockingQueue<>(maxBatchSize * 2);
        this.itemsQueueTimeout = itemsQueueTimeout;
        this.currentBatch = new ArrayList<>(maxBatchSize);
        this.flushThread = Thread.ofPlatform()
                .name("DexEngine-Buffer-%s-".formatted(name), 0)
                .unstarted(() -> {
                    try {
                        flushLoop();
                    } catch (Throwable e) {
                        LOGGER.error("Unexpected error occurred in flush loop", e);
                    }
                });
        this.flushRequestQueue = new ArrayBlockingQueue<>(1);
        this.flushInterval = flushInterval;
        this.flushLock = new ReentrantLock();
        this.statusLock = new ReentrantLock();
        this.meterRegistry = meterRegistry;
        this.circuitBreaker = circuitBreakerRegistry.circuitBreaker("dt.dex.engine.buffer." + name);
    }

    public String name() {
        return name;
    }

    public Status status() {
        return status;
    }

    public boolean acceptsWork() {
        // NB: In the future we might want to include itemsQueue depth here.
        // A queue at capacity won't accept new items, so calls to #add() may
        // time out.
        return status == Status.RUNNING
                && circuitBreaker.getState() != CircuitBreaker.State.OPEN;
    }

    public void start() {
        setStatus(Status.STARTING);

        final List<Tag> commonMeterTags = List.of(Tag.of("buffer", name));
        batchSizeDistribution = DistributionSummary
                .builder("dt.dex.engine.buffer.flush.batch.size")
                .publishPercentileHistogram()
                .tags(commonMeterTags)
                .register(meterRegistry);
        Gauge
                .builder("dt.dex.engine.buffer.items.queued", itemsQueue::size)
                .tags(commonMeterTags)
                .register(meterRegistry);
        itemWaitLatencyTimer = Timer
                .builder("dt.dex.engine.buffer.item.wait.latency")
                .tags(commonMeterTags)
                .register(meterRegistry);
        flushCounter = Counter
                .builder("dt.dex.engine.buffer.flushes")
                .tags(commonMeterTags)
                .register(meterRegistry);
        flushLatencyTimer = Timer
                .builder("dt.dex.engine.buffer.flush.latency")
                .tags(commonMeterTags)
                .register(meterRegistry);

        setStatus(Status.RUNNING);

        flushThread.start();
    }

    @Override
    public void close() {
        LOGGER.debug("{}: Closing", name);
        setStatus(Status.STOPPING);

        if (flushThread.isAlive()) {
            LOGGER.debug("{}: Waiting for flush thread to stop", name);
            try {
                final boolean terminated = flushThread.join(Duration.ofSeconds(3));
                if (!terminated) {
                    LOGGER.warn("{}: Flush thread did not stop in time; Interrupting it", name);
                    flushThread.interrupt();
                }
            } catch (InterruptedException _) {
                LOGGER.warn("{}: Interrupted while waiting for flush thread to stop", name);
                Thread.currentThread().interrupt();
                flushThread.interrupt();
            }
        }
        setStatus(Status.STOPPED);

        // Flush one last time, in case new items were added to the buffer while
        // the executor was shutting down.
        while (!itemsQueue.isEmpty()) {
            LOGGER.debug("{}: Flushing because {} items are still queued", name, itemsQueue.size());
            maybeFlush();
        }

        LOGGER.debug("{}: Closed", name);
    }

    public CompletableFuture<Void> add(T item) throws InterruptedException, TimeoutException {
        if (status != Status.RUNNING) {
            throw new IllegalStateException("Cannot accept new items in current status: " + status);
        }

        final CompletableFuture<Void> future = new CompletableFuture<>();

        final boolean added = itemsQueue.offer(
                new BufferedItem<>(item, System.nanoTime(), future),
                itemsQueueTimeout.toMillis(),
                TimeUnit.MILLISECONDS);
        if (!added) {
            throw new TimeoutException("Timed out while waiting for buffer queue to accept the item");
        }

        if (itemsQueue.size() >= maxBatchSize) {
            // Request a flush to be performed, but don't block
            // if the queue already has a pending request.
            LOGGER.debug("{}: Requesting another flush because {} items are still queued", name, itemsQueue.size());
            boolean _ = flushRequestQueue.offer(true);
        }

        return future;
    }

    private void flushLoop() {
        while (status == Status.RUNNING && !Thread.currentThread().isInterrupted()) {
            try {
                // Block until either a flush is explicitly requested, or the flush interval elapses.
                final Boolean request = flushRequestQueue.poll(flushInterval.toMillis(), TimeUnit.MILLISECONDS);
                if (request != null) {
                    LOGGER.debug("{}: Cutting flush interval short because a flush was explicitly requested", name);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.debug("{}: Interrupted while waiting for next flush to be due", name);
                break;
            }

            try {
                maybeFlush();
            } catch (RuntimeException e) {
                LOGGER.error("{}: An unexpected error occurred during flush", name, e);
            }
        }

        LOGGER.debug("{}: Flush loop exited normally", name);
    }

    private void maybeFlush() {
        final boolean lockAcquired;
        try {
            lockAcquired = flushLock.tryLock(100, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.debug("{}: Interrupted while waiting for flush lock to be acquired", name, e);
            return;
        }

        if (!lockAcquired) {
            LOGGER.warn("{}: Flush lock could not be acquired", name);
            return;
        }

        try {
            // NB: tryAcquirePermission drives state transitions (e.g. OPEN -> HALF_OPEN),
            // so it must be called on every tick to enable recovery, including when the
            // queue is empty. Otherwise, once workers back off via acceptsWork():
            //   1. no items arrive
            //   2. no permission is ever attempted
            //   3. the breaker stays OPEN indefinitely
            //   4. workers never resume polling
            // When permission is denied, we still drain up to maxBatchSize and fail
            // those futures fast with CallNotPermittedException, so producers don't sit on
            // Buffer#add until timeout and the queue doesn't grow unboundedly while the breaker is open.
            final boolean permitted = circuitBreaker.tryAcquirePermission();
            itemsQueue.drainTo(currentBatch, maxBatchSize);

            if (currentBatch.isEmpty()) {
                if (permitted) {
                    // We acquired a permission but have no work to drive a probe.
                    // Release so the next tick with work can acquire instead.
                    circuitBreaker.releasePermission();
                }
                LOGGER.debug("{}: Buffer is empty; Nothing to flush", name);
                return;
            }

            if (!permitted) {
                if (status == Status.RUNNING) {
                    LOGGER.debug("{}: Circuit breaker rejected flush", name);
                }
                final long nowNanos = System.nanoTime();

                for (final BufferedItem<T> item : currentBatch) {
                    item.future().completeExceptionally(
                            createCallNotPermittedException(circuitBreaker));
                    itemWaitLatencyTimer.record(
                            nowNanos - item.addedAtNanos(),
                            TimeUnit.NANOSECONDS);
                }

                currentBatch.clear();
                return;
            }

            batchSizeDistribution.record(currentBatch.size());
            LOGGER.debug("{}: Flushing batch of {} items", name, currentBatch.size());
            final Timer.Sample flushLatencySample = Timer.start();
            final long startNanos = System.nanoTime();
            try {
                final List<T> batchItems = currentBatch.stream().map(BufferedItem::item).collect(Collectors.toList());
                batchConsumer.accept(batchItems);
                circuitBreaker.onSuccess(System.nanoTime() - startNanos, TimeUnit.NANOSECONDS);

                final long nowNanos = System.nanoTime();
                for (final BufferedItem<T> item : currentBatch) {
                    item.future().complete(null);
                    itemWaitLatencyTimer.record(
                            nowNanos - item.addedAtNanos(),
                            TimeUnit.NANOSECONDS);
                }
            } catch (Throwable e) {
                circuitBreaker.onError(System.nanoTime() - startNanos, TimeUnit.NANOSECONDS, e);

                final long nowNanos = System.nanoTime();
                for (final BufferedItem<T> item : currentBatch) {
                    item.future().completeExceptionally(e);
                    itemWaitLatencyTimer.record(
                            nowNanos - item.addedAtNanos(),
                            TimeUnit.NANOSECONDS);
                }
            } finally {
                flushCounter.increment();
                flushLatencySample.stop(flushLatencyTimer);
                currentBatch.clear();
            }

            if (itemsQueue.size() >= maxBatchSize) {
                // Request another flush if there's still at least
                // a full batch worth of items queued.
                boolean _ = flushRequestQueue.offer(true);
            }
        } finally {
            flushLock.unlock();
        }
    }

    private void setStatus(Status newStatus) {
        statusLock.lock();
        try {
            if (this.status == newStatus) {
                return;
            }

            if (this.status.canTransitionTo(newStatus)) {
                this.status = newStatus;
                return;
            }

            throw new IllegalStateException(
                    "Can not transition from status %s to %s".formatted(this.status, newStatus));
        } finally {
            statusLock.unlock();
        }
    }

}
