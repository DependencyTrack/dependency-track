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
package org.dependencytrack.v4migrator.load;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Emits a periodic "still loading" heartbeat while an INSERT…SELECT runs, plus a final
 * summary line with rows/s. The load statement itself runs in one transaction on the
 * caller's thread; the heartbeat fires from a daemon scheduler so JVM shutdown is not
 * blocked.
 *
 * <p>One instance per {@link LoadPhase} run. Call {@link #start} immediately before the
 * load statement, then exactly one of {@link #done} or {@link #fail} afterwards.
 */
final class LoadProgressReporter implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoadProgressReporter.class);
    private static final Duration DEFAULT_HEARTBEAT = Duration.ofSeconds(5);

    private final ScheduledExecutorService scheduler;
    private final Duration heartbeat;
    private final Consumer<String> sink;

    private long startNanos;
    private String tableName = "";
    private long expectedRows = -1L;
    private ScheduledFuture<?> task;

    LoadProgressReporter() {
        this(DEFAULT_HEARTBEAT, LOGGER::info);
    }

    LoadProgressReporter(final Duration heartbeat, final Consumer<String> sink) {
        this.heartbeat = heartbeat;
        this.sink = sink;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            final Thread t = new Thread(r, "load-progress");
            t.setDaemon(true);
            return t;
        });
    }

    void start(final String tableName, final long expectedRows) {
        this.tableName = tableName;
        this.expectedRows = expectedRows;
        this.startNanos = System.nanoTime();
        final long periodMs = heartbeat.toMillis();
        this.task = scheduler.scheduleAtFixedRate(this::tick, periodMs, periodMs, TimeUnit.MILLISECONDS);
    }

    void done(final long actualRows) {
        cancel();
        final long ms = elapsedMs();
        final long rate = ms > 0 ? (actualRows * 1000L) / ms : 0L;
        sink.accept(String.format("  -> %s: %d rows in %d ms (%d rows/s)", tableName, actualRows, ms, rate));
    }

    void fail() {
        cancel();
    }

    @Override
    public void close() {
        cancel();
        scheduler.shutdownNow();
    }

    private void cancel() {
        if (task != null) {
            task.cancel(false);
            task = null;
        }
    }

    private long elapsedMs() {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    private void tick() {
        try {
            final long ms = elapsedMs();
            final String elapsed = formatElapsed(ms);
            if (expectedRows >= 0) {
                sink.accept(String.format("  .. %s: still loading after %s (expected %d rows)",
                    tableName, elapsed, expectedRows));
            } else {
                sink.accept(String.format("  .. %s: still loading after %s", tableName, elapsed));
            }
        } catch (final RuntimeException e) {
            // Never let a heartbeat failure escape — that would kill the scheduled task silently
            // *and* doom subsequent ticks. Log once and continue.
            LOGGER.warn("Heartbeat tick failed for {}", tableName, e);
        }
    }

    static String formatElapsed(final long ms) {
        final long totalSec = ms / 1000L;
        final long h = totalSec / 3600L;
        final long m = (totalSec % 3600L) / 60L;
        final long s = totalSec % 60L;
        if (h > 0) {
            return String.format("%dh %dm %ds", h, m, s);
        }
        if (m > 0) {
            return String.format("%dm %ds", m, s);
        }
        return String.format("%ds", s);
    }
}
