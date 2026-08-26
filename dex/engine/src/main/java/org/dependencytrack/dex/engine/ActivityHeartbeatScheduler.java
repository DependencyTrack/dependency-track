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

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.Closeable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.dependencytrack.dex.engine.MdcKeys.MDC_ACTIVITY_NAME;
import static org.dependencytrack.dex.engine.MdcKeys.MDC_ACTIVITY_TASK_EXECUTION_ID;
import static org.dependencytrack.dex.engine.MdcKeys.MDC_WORKFLOW_RUN_ID;

final class ActivityHeartbeatScheduler implements Closeable {

    @FunctionalInterface
    interface LockRenewer {

        @Nullable
        CompletableFuture<TaskLock> tryRenew(ActivityTaskId taskId, TaskLock currentLock, Duration lockTimeout);
    }

    private record Registration(
            String activityName,
            ActivityTaskId taskId,
            String executionId,
            Duration lockTimeout,
            Supplier<TaskLock> lockGetter,
            Consumer<TaskLock> lockSetter,
            Future<?> activityFuture,
            AtomicReference<@Nullable CompletableFuture<TaskLock>> pendingLockRenewal) {}

    private static final Logger LOGGER = LoggerFactory.getLogger(ActivityHeartbeatScheduler.class);
    private static final int LOCK_RENEWAL_MARGIN_DIVISOR = 3;
    private static final int GIVE_UP_MARGIN_INTERVALS = 2;
    private static final Duration UNREGISTER_RENEWAL_SETTLE_TIMEOUT = Duration.ofSeconds(10);

    private final LockRenewer lockRenewer;
    private final Duration interval;
    private final Duration giveUpMargin;
    private final Clock clock;
    private final Map<Future<?>, Registration> registrationByActivityFuture;
    private final ScheduledExecutorService scheduler;

    ActivityHeartbeatScheduler(LockRenewer lockRenewer, Duration interval) {
        this(lockRenewer, interval, Clock.systemUTC());
    }

    ActivityHeartbeatScheduler(LockRenewer lockRenewer, Duration interval, Clock clock) {
        this.lockRenewer = lockRenewer;
        this.interval = interval;
        this.giveUpMargin = interval.multipliedBy(GIVE_UP_MARGIN_INTERVALS);
        this.clock = clock;
        this.registrationByActivityFuture = new ConcurrentHashMap<>();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            final var thread = new Thread(runnable, "DexEngine-ActivityHeartbeatScheduler");
            thread.setDaemon(true);
            return thread;
        });
    }

    void start() {
        scheduler.scheduleWithFixedDelay(
                this::processRegistrations, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
    }

    void register(
            String activityName,
            ActivityTaskId taskId,
            String executionId,
            Duration lockTimeout,
            Supplier<TaskLock> lockGetter,
            Consumer<TaskLock> lockSetter,
            Future<?> activityFuture) {
        registrationByActivityFuture.put(
                activityFuture,
                new Registration(
                        activityName,
                        taskId,
                        executionId,
                        lockTimeout,
                        lockGetter,
                        lockSetter,
                        activityFuture,
                        new AtomicReference<>()));
    }

    void unregister(Future<?> activityFuture) {
        final Registration registration = registrationByActivityFuture.get(activityFuture);
        if (registration == null) {
            return;
        }

        final CompletableFuture<TaskLock> pendingRenewal;
        synchronized (registration) {
            registrationByActivityFuture.remove(activityFuture);
            pendingRenewal = registration.pendingLockRenewal().get();
        }
        if (pendingRenewal == null || pendingRenewal.isDone()) {
            return;
        }

        // An in-flight renewal may already have bumped the lock version in the database.
        // Completing the task with the previous version would fail the version check,
        // discarding the finished execution and provoking a duplicate run. Wait for the
        // renewal to settle so the task holds its current lock before it is completed.
        try {
            pendingRenewal.get(UNREGISTER_RENEWAL_SETTLE_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.debug("Interrupted while waiting for pending renewal to complete");
        } catch (ExecutionException e) {
            if (isLockLost(e.getCause())) {
                LOGGER.warn("""
                        Lock was taken over by another worker while the activity was completing; \
                        the completion will be rejected, and the task will be executed again""");
            } else {
                // A transient renewal failure did not bump the lock version,
                // so the version check on task completion passes against the previous lock.
                LOGGER.debug("Lock renewal failed while waiting for it to complete", e.getCause());
            }
        } catch (TimeoutException e) {
            LOGGER.warn("""
                            Lock renewal did not complete within {}; completing the task may \
                            race the renewal and be rejected, provoking a duplicate execution""", UNREGISTER_RENEWAL_SETTLE_TIMEOUT);
        }
    }

    void processRegistrations() {
        for (final Registration registration : registrationByActivityFuture.values()) {
            MDC.put(MDC_WORKFLOW_RUN_ID, registration.taskId().workflowRunId().toString());
            MDC.put(MDC_ACTIVITY_NAME, registration.activityName());
            MDC.put(MDC_ACTIVITY_TASK_EXECUTION_ID, registration.executionId());
            try {
                process(registration);
            } catch (RuntimeException e) {
                LOGGER.error("Failed to process heartbeat", e);
            } finally {
                MDC.remove(MDC_WORKFLOW_RUN_ID);
                MDC.remove(MDC_ACTIVITY_NAME);
                MDC.remove(MDC_ACTIVITY_TASK_EXECUTION_ID);
            }
        }
    }

    private void process(Registration registration) {
        // NB: We must read the pending renewal before the lock, because the renewal callback
        // publishes the new lock before its future completes, so an absent or completed pending
        // renewal guarantees the lock read below is current.
        final CompletableFuture<TaskLock> pendingRenewal =
                registration.pendingLockRenewal().get();
        final boolean isRenewalInFlight = pendingRenewal != null && !pendingRenewal.isDone();

        final Instant now = clock.instant();
        final Instant expiresAt = registration.lockGetter().get().expiresAt();

        if (isRenewalInFlight) {
            // The pending renewal will either extend the lock or cancel the activity
            // when it completes, and the local expiry may be stale until then.
            // But once the lock has fully expired, stop the activity regardless.
            // It must not keep running under a lock we no longer hold.
            if (!now.isBefore(expiresAt)) {
                onLockLost(registration, "its lock expired before an in-flight renewal completed");
            }

            return;
        }

        // The lock will expire before it can be renewed again, or already has.
        // Another worker may take the task over, so stop the activity now instead of
        // letting it run under a lock we no longer hold.
        if (!now.isBefore(expiresAt.minus(giveUpMargin))) {
            onLockLost(registration, "its lock expired before it could be renewed");
            return;
        }

        // Debounce heartbeats such that they're only emitted once the current
        // lock is close to expiry, i.e. within the renewal margin.
        if (now.isBefore(expiresAt.minus(registration.lockTimeout().dividedBy(LOCK_RENEWAL_MARGIN_DIVISOR)))) {
            return;
        }

        synchronized (registration) {
            if (!registrationByActivityFuture.containsKey(registration.activityFuture())) {
                return;
            }

            final CompletableFuture<TaskLock> renewalFuture = lockRenewer.tryRenew(
                    registration.taskId(), registration.lockGetter().get(), registration.lockTimeout());
            if (renewalFuture == null) {
                return;
            }

            // NB: The stored future completes only after the callback ran and the new
            // lock was set. unregister() relies on that. Since only the scheduler thread
            // starts renewals, and never while one is pending, no two renewals can
            // update the same lock at once.
            registration.pendingLockRenewal().set(renewalFuture.whenComplete((newLock, error) -> {
                if (error == null && newLock != null) {
                    registration.lockSetter().accept(newLock);
                } else if (isLockLost(error)) {
                    onLockLost(registration, "its lock was taken over by another worker");
                }

                // NB: Any other error is transient. The deadline checks earlier in the
                // method cancel the activity if we cannot renew before the lock expires.
            }));
        }
    }

    @Override
    public void close() {
        scheduler.shutdownNow();
        try {
            if (!scheduler.awaitTermination(3, TimeUnit.SECONDS)) {
                LOGGER.warn("Heartbeat scheduler did not terminate in time");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        registrationByActivityFuture.clear();
    }

    static Duration minSupportedLockTimeout(Duration interval) {
        // To guarantee a scheduler run happens between the start of the renewal window and
        // the give-up deadline, the window must span at least one interval, i.e.:
        //   lockTimeout / RENEWAL_MARGIN_DIVISOR - GIVE_UP_MARGIN_INTERVALS * interval >= interval
        // Shorter locks would be cancelled without a renewal ever being attempted.
        return interval.multipliedBy(LOCK_RENEWAL_MARGIN_DIVISOR * (GIVE_UP_MARGIN_INTERVALS + 1));
    }

    private void onLockLost(Registration registration, String reason) {
        if (registrationByActivityFuture.remove(registration.activityFuture()) == null) {
            return;
        }

        LOGGER.warn("Cancelling execution because {}", reason);
        registration.activityFuture().cancel(/* mayInterruptIfRunning */ true);
    }

    private static boolean isLockLost(@Nullable Throwable error) {
        final Throwable cause = error instanceof CompletionException ? error.getCause() : error;
        return cause instanceof TaskLockLostException;
    }
}
