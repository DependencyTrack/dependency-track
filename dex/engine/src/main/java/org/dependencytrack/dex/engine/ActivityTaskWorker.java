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
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.dex.engine.TaskEvent.ActivityTaskAbandonedEvent;
import org.dependencytrack.dex.engine.TaskEvent.ActivityTaskCompletedEvent;
import org.dependencytrack.dex.engine.TaskEvent.ActivityTaskFailedEvent;
import org.dependencytrack.dex.engine.persistence.command.PollActivityTaskCommand;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;

final class ActivityTaskWorker extends AbstractTaskWorker<ActivityTask> {

    private final DexEngineImpl engine;
    private final MetadataRegistry metadataRegistry;
    private final String queueName;
    private final List<PollActivityTaskCommand> pollCommands;
    private final ExecutorService executionExecutor;

    ActivityTaskWorker(
            final String name,
            final DexEngineImpl engine,
            final Duration minPollInterval,
            final IntervalFunction pollBackoffIntervalFunction,
            final MetadataRegistry metadataRegistry,
            final String queueName,
            final int maxConcurrency,
            final MeterRegistry meterRegistry) {
        super(name, minPollInterval, pollBackoffIntervalFunction, maxConcurrency, meterRegistry);
        this.engine = requireNonNull(engine, "engine must not be null");
        this.metadataRegistry = requireNonNull(metadataRegistry, "metadataRegistry must not be null");
        this.queueName = requireNonNull(queueName, "queueName must not be null");
        this.pollCommands = metadataRegistry.getAllActivityMetadata().stream()
                .map(metadata -> new PollActivityTaskCommand(metadata.name(), metadata.lockTimeout()))
                .toList();
        this.executionExecutor = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual()
                        .name("%s-%s-ActivityExecutor".formatted(getClass().getSimpleName(), name), 0)
                        .factory());
    }

    @Override
    List<ActivityTask> poll(final int limit) {
        return engine.pollActivityTasks(queueName, pollCommands, limit);
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    void process(final ActivityTask task) {
        try (var ignoredMdcWorkflowRunId = MDC.putCloseable("workflowRunId", task.id().workflowRunId().toString());
             var ignoredMdcActivityName = MDC.putCloseable("activityName", task.activityName());
             var ignoredMdcActivityTaskAttempt = MDC.putCloseable("activityTaskAttempt", String.valueOf(task.attempt()))) {
            final ActivityMetadata activityMetadata;
            try {
                activityMetadata = metadataRegistry.getActivityMetadata(task.activityName());
            } catch (NoSuchElementException e) {
                logger.warn("Activity does not exist");
                abandon(task);
                return;
            }

            final var ctx = new ActivityContextImpl(engine, task, activityMetadata.lockTimeout());
            final var arg = activityMetadata.argumentConverter().convertFromPayload(task.argument());

            final Future<Object> future;
            try {
                future = executionExecutor.submit(
                        () -> activityMetadata.executor().execute(ctx, arg));
            } catch (RejectedExecutionException e) {
                logger.debug("Execution executor is shut down; Abandoning task");
                abandon(task);
                return;
            }

            try {
                final Object activityResult = future.get();
                final Payload result = activityMetadata.resultConverter().convertToPayload(activityResult);
                engine.onTaskEvent(new ActivityTaskCompletedEvent(task, result));
            } catch (ExecutionException e) {
                final Throwable cause = e.getCause();
                if (cause instanceof InterruptedException) {
                    logger.debug("Activity was interrupted; Abandoning task");
                    abandon(task);
                } else {
                    final Instant retryAt = computeRetryAt(task, cause);
                    if (retryAt == null) {
                        logger.warn("Activity failed terminally after {} attempt(s)", task.attempt(), cause);
                    } else {
                        logger.warn(
                                "Activity failed; Next retry due at {} (attempt {}/{})",
                                retryAt, task.attempt() + 1, task.retryPolicy().maxAttempts(), cause);
                    }
                    engine.onTaskEvent(new ActivityTaskFailedEvent(task, cause, retryAt));
                }
            } catch (InterruptedException e) {
                logger.debug("Interrupted while waiting for activity execution to complete; Abandoning task");
                future.cancel(true);
                abandon(task);
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    void abandon(final ActivityTask task) {
        engine.onTaskEvent(new ActivityTaskAbandonedEvent(task));
    }

    @Override
    public void close() {
        executionExecutor.shutdownNow();
        try {
            if (!executionExecutor.awaitTermination(3, TimeUnit.SECONDS)) {
                logger.warn("Activity executor did not terminate in time");
            }
        } catch (InterruptedException e) {
            logger.warn("Interrupted while waiting for activity executor to terminate");
            Thread.currentThread().interrupt();
        }
        super.close();
    }

    private static @Nullable Instant computeRetryAt(ActivityTask task, Throwable cause) {
        final RetryPolicy retryPolicy = task.retryPolicy();
        final boolean isTerminal =
                cause instanceof ApplicationFailureException afe
                        && afe.isTerminal();
        if (isTerminal || retryPolicy.maxAttempts() <= task.attempt()) {
            return null;
        }

        final Duration retryAfter =
                cause instanceof ApplicationFailureException afe
                        ? afe.retryAfter()
                        : null;

        final Duration retryDelay;
        if (retryAfter != null) {
            retryDelay = retryAfter;
        } else {
            final var intervalFunc =
                    IntervalFunction.ofExponentialRandomBackoff(
                            retryPolicy.initialDelay(),
                            retryPolicy.delayMultiplier(),
                            retryPolicy.delayRandomizationFactor(),
                            retryPolicy.maxDelay());
            retryDelay = Duration.ofMillis(intervalFunc.apply(task.attempt() + 1));
        }

        return Instant.now().plus(retryDelay);
    }

}
