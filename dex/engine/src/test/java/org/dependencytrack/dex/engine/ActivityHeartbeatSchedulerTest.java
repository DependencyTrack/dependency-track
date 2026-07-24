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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static java.util.concurrent.CompletableFuture.completedFuture;
import static java.util.concurrent.CompletableFuture.failedFuture;
import static org.assertj.core.api.Assertions.assertThat;

class ActivityHeartbeatSchedulerTest {

    private static final Duration HEARTBEAT_INTERVAL = Duration.ofSeconds(1);
    private static final Duration LOCK_TIMEOUT = Duration.ofSeconds(30);

    private MutableClock clock;
    private RecordingLockRenewer lockRenewer;
    private ActivityHeartbeatScheduler scheduler;

    @BeforeEach
    void beforeEach() {
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        lockRenewer = new RecordingLockRenewer();
        scheduler = new ActivityHeartbeatScheduler(lockRenewer, HEARTBEAT_INTERVAL, clock);
    }

    @AfterEach
    void afterEach() {
        scheduler.close();
    }

    @Test
    void shouldNotRenewWhenLockHasPlentyOfTimeLeft() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(30)));
        final var activityFuture = new CompletableFuture<Void>();
        register(lock, activityFuture);

        scheduler.processRegistrations();

        assertThat(lockRenewer.calls.get()).isZero();
        assertThat(activityFuture).isNotCancelled();
    }

    @Test
    void shouldRenewWhenLockIsCloseToExpiry() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(5), 1));
        final var activityFuture = new CompletableFuture<Void>();
        register(lock, activityFuture);

        final TaskLock renewedLock = lockExpiringIn(Duration.ofSeconds(35), 2);
        lockRenewer.respondWith(() -> completedFuture(renewedLock));

        scheduler.processRegistrations();

        assertThat(lockRenewer.calls.get()).isOne();
        assertThat(lock.get()).isEqualTo(renewedLock);
        assertThat(activityFuture).isNotCancelled();
    }

    @Test
    void shouldRetryRenewalOnNextRunAfterBufferRejection() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(5)));
        register(lock, new CompletableFuture<>());

        lockRenewer.respondWith(() -> null);
        scheduler.processRegistrations();
        assertThat(lockRenewer.calls.get()).isOne();

        scheduler.processRegistrations();
        assertThat(lockRenewer.calls.get()).isEqualTo(2);
        assertThat(lock.get().version()).isOne();
    }

    @Test
    void shouldNotCancelActivityWhenRenewalFailsTransiently() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(5)));
        final var activityFuture = new CompletableFuture<Void>();
        register(lock, activityFuture);

        // A transient failure (NOT a lost lock!) must neither cancel the activity nor
        // advance the lock, so a completion can still succeed against the current version.
        lockRenewer.respondWith(() -> failedFuture(new IllegalStateException("transient")));
        scheduler.processRegistrations();
        assertThat(activityFuture).isNotCancelled();
        assertThat(lockRenewer.calls.get()).isOne();
        assertThat(lock.get().version()).isOne();

        // The lock is still close to expiry, so the next run retries the renewal.
        final TaskLock renewedLock = lockExpiringIn(Duration.ofSeconds(35), 2);
        lockRenewer.respondWith(() -> completedFuture(renewedLock));
        scheduler.processRegistrations();
        assertThat(lockRenewer.calls.get()).isEqualTo(2);
        assertThat(lock.get()).isEqualTo(renewedLock);
        assertThat(activityFuture).isNotCancelled();
    }

    @Test
    void shouldCancelActivityWhenLockWasTakenOver() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(5)));
        final var activityFuture = new CompletableFuture<Void>();
        register(lock, activityFuture);

        lockRenewer.respondWith(() -> failedFuture(new TaskLockLostException()));
        scheduler.processRegistrations();

        assertThat(activityFuture).isCancelled();

        lockRenewer.respondWith(() -> completedFuture(lockExpiringIn(Duration.ofSeconds(35))));
        scheduler.processRegistrations();
        assertThat(lockRenewer.calls.get()).isOne();
    }

    @Test
    void shouldCancelActivityWhenLockExpiresBeforeItCanBeRenewed() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(1)));
        final var activityFuture = new CompletableFuture<Void>();
        register(lock, activityFuture);

        scheduler.processRegistrations();

        assertThat(activityFuture).isCancelled();
        assertThat(lockRenewer.calls.get()).isZero();
    }

    @Test
    void shouldNotStartOverlappingRenewalsForTheSameTask() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(5)));
        register(lock, new CompletableFuture<>());

        lockRenewer.respondWith(CompletableFuture::new);
        scheduler.processRegistrations();
        scheduler.processRegistrations();

        assertThat(lockRenewer.calls.get()).isOne();
    }

    @Test
    void shouldNotGiveUpWhileRenewalIsInFlight() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(5)));
        final var activityFuture = new CompletableFuture<Void>();
        register(lock, activityFuture);

        final var renewalFuture = new CompletableFuture<TaskLock>();
        lockRenewer.respondWith(() -> renewalFuture);
        scheduler.processRegistrations();
        assertThat(lockRenewer.calls.get()).isOne();

        // Local lock view is close to expiry, but the pending renewal may still extend it.
        clock.setInstant(clock.instant().plus(Duration.ofMillis(4_500)));
        scheduler.processRegistrations();
        assertThat(activityFuture).isNotCancelled();

        // Once the local lock view has fully expired, pending renewal or not,
        // the activity must no longer run under it.
        clock.setInstant(clock.instant().plus(Duration.ofSeconds(1)));
        scheduler.processRegistrations();
        assertThat(activityFuture).isCancelled();
    }

    @Test
    void shouldAwaitInFlightRenewalOnUnregister() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(5), 1));
        final var activityFuture = new CompletableFuture<Void>();
        register(lock, activityFuture);

        final var renewalFuture = new CompletableFuture<TaskLock>();
        lockRenewer.respondWith(() -> renewalFuture);
        scheduler.processRegistrations();
        assertThat(lockRenewer.calls.get()).isOne();

        final TaskLock renewedLock = lockExpiringIn(Duration.ofSeconds(35), 2);
        Thread.ofPlatform().start(() -> {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            renewalFuture.complete(renewedLock);
        });
        scheduler.unregister(activityFuture);

        // unregister must only return once the renewed lock is published,
        // so the task is completed under its current lock version.
        assertThat(lock.get()).isEqualTo(renewedLock);
    }

    @Test
    void shouldStopRenewingAfterUnregister() {
        final var lock = new AtomicReference<>(lockExpiringIn(Duration.ofSeconds(5)));
        final var activityFuture = new CompletableFuture<>();
        register(lock, activityFuture);

        scheduler.unregister(activityFuture);
        scheduler.processRegistrations();

        assertThat(lockRenewer.calls.get()).isZero();
    }

    private void register(
            AtomicReference<TaskLock> lock,
            CompletableFuture<?> activityFuture) {
        final var taskId = new ActivityTaskId("queue", UUID.randomUUID(), 1);
        scheduler.register("activityName", taskId, "test-execution", LOCK_TIMEOUT, lock::get, lock::set, activityFuture);
    }

    private TaskLock lockExpiringIn(Duration remaining) {
        return lockExpiringIn(remaining, 1);
    }

    private TaskLock lockExpiringIn(Duration remaining, int version) {
        return new TaskLock(clock.instant().plus(remaining), version);
    }

    private static final class RecordingLockRenewer implements ActivityHeartbeatScheduler.LockRenewer {

        private final AtomicInteger calls = new AtomicInteger();
        private volatile Supplier<CompletableFuture<TaskLock>> response =
                () -> completedFuture(new TaskLock(Instant.now(), 1));

        void respondWith(Supplier<CompletableFuture<TaskLock>> response) {
            this.response = response;
        }

        @Override
        public CompletableFuture<TaskLock> tryRenew(
                @NonNull ActivityTaskId taskId,
                @NonNull TaskLock currentLock,
                @NonNull Duration lockTimeout) {
            calls.incrementAndGet();
            return response.get();
        }

    }

    private static final class MutableClock extends Clock {

        private volatile Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        void setInstant(Instant instant) {
            this.instant = instant;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

    }

}
