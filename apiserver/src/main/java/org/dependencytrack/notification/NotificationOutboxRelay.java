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
package org.dependencytrack.notification;

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.persistence.jdbi.AdvisoryLocks;
import org.dependencytrack.persistence.jdbi.NotificationOutboxDao;
import org.dependencytrack.proto.internal.workflow.v1.PublishNotificationWorkflowArg;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;
import static java.util.Objects.requireNonNull;
import static org.dependencytrack.common.MdcKeys.MDC_NOTIFICATION_ID;
import static org.dependencytrack.notification.NotificationModelConverter.convert;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

/**
 * Outbox relay of notifications.
 *
 * @since 5.0.0
 */
final class NotificationOutboxRelay implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationOutboxRelay.class);
    private static final long ADVISORY_LOCK_ID = 275439834778508297L;
    private static final String EXECUTOR_NAME = "NotificationOutboxRelay";
    private static final List<Tag> COMMON_METER_TAGS = List.of(Tag.of("outboxName", "notifications"));
    private static final String OUTCOME_METER_TAG_NAME = "outcome";

    private final DexEngine dexEngine;
    private final FileStorage fileStorage;
    private final Function<Handle, NotificationRouter> routerFactory;
    private final MeterRegistry meterRegistry;
    private final long pollIntervalMillis;
    private final int batchSize;
    private final int largeNotificationThresholdBytes;
    private final BlockingQueue<Notification> currentBatch;
    private final IntervalFunction backoffIntervalFunction;
    private @Nullable ScheduledExecutorService executorService;
    private @Nullable MeterProvider<Timer> cycleLatencyTimer;
    private @Nullable MeterProvider<Counter> cycleCounter;
    private @Nullable Timer pollLatencyTimer;
    private @Nullable Timer sendLatencyTimer;
    private @Nullable MeterProvider<DistributionSummary> sentDistribution;

    public NotificationOutboxRelay(
            DexEngine dexEngine,
            FileStorage fileStorage,
            Function<Handle, NotificationRouter> routerFactory,
            MeterRegistry meterRegistry,
            long pollIntervalMillis,
            int batchSize,
            int largeNotificationThresholdBytes) {
        this.dexEngine = requireNonNull(dexEngine, "dexEngine must not be null");
        this.fileStorage = requireNonNull(fileStorage, "fileStorage must not be null");
        this.routerFactory = requireNonNull(routerFactory, "routerFactory must not be null");
        this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
        if (pollIntervalMillis <= 0) {
            throw new IllegalArgumentException("pollIntervalMillis must be greater than 0");
        }
        if (batchSize <= 0) {
            throw new IllegalArgumentException("batchSize must be greater than 0");
        }
        if (largeNotificationThresholdBytes <= 0) {
            throw new IllegalArgumentException("largeNotificationThresholdBytes must be greater than 0");
        }
        this.pollIntervalMillis = pollIntervalMillis;
        this.batchSize = batchSize;
        this.largeNotificationThresholdBytes = largeNotificationThresholdBytes;
        this.currentBatch = new ArrayBlockingQueue<>(batchSize);
        this.backoffIntervalFunction = ofExponentialRandomBackoff(
                /* initialDelay */ pollIntervalMillis,
                /* multiplier */ 1.5,
                /* maxDelay */ TimeUnit.MINUTES.toMillis(3));
    }

    public void start() {
        // Obviously this check isn't thread safe, but we expect this
        // method to only be called once on startup.
        if (executorService != null) {
            throw new IllegalStateException("Already started");
        }

        executorService = Executors.newSingleThreadScheduledExecutor(
                BasicThreadFactory.builder()
                        .uncaughtExceptionHandler((thread, throwable) ->
                                LOGGER.error("Uncaught exception in thread {}", thread.getName(), throwable))
                        .namingPattern(EXECUTOR_NAME + "-%d")
                        .build());
        new ExecutorServiceMetrics(executorService, EXECUTOR_NAME, null)
                .bindTo(meterRegistry);

        cycleLatencyTimer = Timer
                .builder("dt.outbox.relay.cycle.latency")
                .tags(COMMON_METER_TAGS)
                .description("Latency of a relay cycle")
                .withRegistry(meterRegistry);

        cycleCounter = Counter
                .builder("dt.outbox.relay.cycles")
                .tags(COMMON_METER_TAGS)
                .description("Number of relay cycles")
                .withRegistry(meterRegistry);

        pollLatencyTimer = Timer
                .builder("dt.outbox.relay.poll.latency")
                .tags(COMMON_METER_TAGS)
                .description("Latency of polls from the outbox table")
                .register(meterRegistry);

        sendLatencyTimer = Timer
                .builder("dt.outbox.relay.send.latency")
                .tags(COMMON_METER_TAGS)
                .description("Latency of messages being sent")
                .register(meterRegistry);

        sentDistribution = DistributionSummary
                .builder("dt.outbox.relay.messages.sent")
                .tags(COMMON_METER_TAGS)
                .description("Number of messages sent")
                .withRegistry(meterRegistry);

        executorService.schedule(
                () -> run(0),
                pollIntervalMillis,
                TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (executorService != null) {
            executorService.close();
            executorService = null;
        }
    }

    private void run(int failureBackoffCount) {
        final Timer.Sample cycleLatencySample = Timer.start();
        try {
            final RelayCycleOutcome cycleOutcome = executeRelayCycle();
            cycleCounter.withTag(OUTCOME_METER_TAG_NAME, cycleOutcome.name()).increment();
            cycleLatencySample.stop(cycleLatencyTimer.withTag(OUTCOME_METER_TAG_NAME, cycleOutcome.name()));

            executorService.schedule(
                    () -> run(0),
                    pollIntervalMillis,
                    TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            LOGGER.debug("Next poll could not be scheduled, likely because the executor was shut down", e);
        } catch (Throwable t) {
            cycleCounter.withTag(OUTCOME_METER_TAG_NAME, RelayCycleOutcome.FAILED.name()).increment();
            cycleLatencySample.stop(cycleLatencyTimer.withTag(OUTCOME_METER_TAG_NAME, RelayCycleOutcome.FAILED.name()));

            // Ensure that we don't keep thrashing external services if we run into errors.
            final long backoffDelayMillis = backoffIntervalFunction.apply(failureBackoffCount + 1);
            LOGGER.error("Failed to relay messages, backing off for {}ms", backoffDelayMillis, t);
            executorService.schedule(
                    () -> run(failureBackoffCount + 1),
                    backoffDelayMillis,
                    TimeUnit.MILLISECONDS);
        } finally {
            currentBatch.clear();
        }
    }

    private enum RelayCycleOutcome {
        COMPLETED,
        FAILED,
        SKIPPED
    }

    private RelayCycleOutcome executeRelayCycle() {
        return inJdbiTransaction(handle -> {
            // Acquire advisory lock to prevent concurrent relay from multiple instances.
            //
            // Ideally we want relays to happen in the order in which notifications were
            // emitted. Work-stealing polling with FOR UPDATE SKIP LOCKED would mess with ordering.
            //
            // The lack of concurrency is in part mitigated by processing notifications in batches.
            final boolean lockAcquired = AdvisoryLocks.tryAcquire(handle, ADVISORY_LOCK_ID);
            if (!lockAcquired) {
                LOGGER.debug("Lock already acquired by another instance");
                return RelayCycleOutcome.SKIPPED;
            }

            final Timer.Sample pollLatencySample = Timer.start();
            try {
                final var outboxDao = handle.attach(NotificationOutboxDao.class);
                currentBatch.addAll(outboxDao.poll(batchSize));
            } finally {
                pollLatencySample.stop(pollLatencyTimer);
            }

            if (currentBatch.isEmpty()) {
                return RelayCycleOutcome.COMPLETED;
            }

            final NotificationRouter router = routerFactory.apply(handle);
            final List<NotificationRouter.Result> routerResults = router.route(currentBatch);
            LOGGER.debug("Router generated {} results", routerResults.size());
            if (routerResults.isEmpty()) {
                return RelayCycleOutcome.COMPLETED;
            }

            final Timer.Sample sendLatencySample = Timer.start();
            try {
                sendAll(routerResults);
            } finally {
                sendLatencySample.stop(sendLatencyTimer);
            }

            for (final Notification notification : currentBatch) {
                sentDistribution
                        .withTags(List.of(
                                Tag.of("level", convert(notification.getLevel()).name()),
                                Tag.of("scope", convert(notification.getScope()).name()),
                                Tag.of("group", convert(notification.getGroup()).name())))
                        .record(1);
            }

            return RelayCycleOutcome.COMPLETED;
        });
    }

    private void sendAll(Collection<NotificationRouter.Result> routerResults) {
        final var createRunRequests = new ArrayList<CreateWorkflowRunRequest<?>>(routerResults.size());

        for (final var routerResult : routerResults) {
            final Notification notification = routerResult.notification();

            try (var _ = MDC.putCloseable(MDC_NOTIFICATION_ID, notification.getId())) {
                final var workflowArgBuilder =
                        PublishNotificationWorkflowArg.newBuilder()
                                .setNotificationId(notification.getId())
                                .addAllNotificationRuleNames(routerResult.ruleNames());

                // Large payloads have the potential to slow down the dex engine,
                // as they're stored in the workflow history. Some notifications
                // can be large, e.g. BOM_CONSUMED.
                //
                // If a notification exceeds the configured size threshold,
                // offload it to file storage and send the file's metadata
                // as workflow argument instead. It is the workflow's responsibility
                // to ensure that the file is deleted.
                if (notification.getSerializedSize() > largeNotificationThresholdBytes) {
                    LOGGER.warn(
                            "Notification size {}b exceeds large threshold of {}b; Will offload to file storage",
                            notification.getSerializedSize(),
                            largeNotificationThresholdBytes);

                    try {
                        final FileMetadata fileMetadata = fileStorage.store(
                                "notifications/%s.proto".formatted(notification.getId()),
                                "application/protobuf",
                                new ByteArrayInputStream(notification.toByteArray()));
                        workflowArgBuilder.setNotificationFileMetadata(fileMetadata);
                    } catch (IOException e) {
                        throw new UncheckedIOException("Failed to store notification file", e);
                    }
                } else {
                    workflowArgBuilder.setNotification(notification);
                }

                createRunRequests.add(
                        new CreateWorkflowRunRequest<>(PublishNotificationWorkflow.class)
                                .withWorkflowInstanceId("publish-notification:" + notification.getId())
                                .withArgument(workflowArgBuilder.build()));
            }
        }

        dexEngine.createRuns(createRunRequests);
    }

}
