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

import com.google.protobuf.util.Timestamps;
import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.MeterRegistry;
import org.dependencytrack.dex.engine.TaskEvent.WorkflowTaskAbandonedEvent;
import org.dependencytrack.dex.engine.TaskEvent.WorkflowTaskCompletedEvent;
import org.dependencytrack.dex.engine.persistence.command.PollWorkflowTaskCommand;
import org.dependencytrack.dex.proto.event.v1.RunStarted;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.dex.proto.event.v1.WorkflowTaskCompleted;
import org.dependencytrack.dex.proto.event.v1.WorkflowTaskStarted;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.BooleanSupplier;

import static java.util.Objects.requireNonNull;

final class WorkflowTaskWorker extends AbstractTaskWorker<WorkflowTask> {

    private final DexEngineImpl engine;
    private final MetadataRegistry metadataRegistry;
    private final String queueName;
    private final List<PollWorkflowTaskCommand> pollCommands;

    WorkflowTaskWorker(
            final String name,
            final DexEngineImpl engine,
            final MetadataRegistry metadataRegistry,
            final String queueName,
            final Duration minPollInterval,
            final IntervalFunction pollBackoffIntervalFunction,
            final int maxConcurrency,
            final MeterRegistry meterRegistry,
            final BooleanSupplier downstreamAcceptsWork) {
        super(name, minPollInterval, pollBackoffIntervalFunction, maxConcurrency, meterRegistry, downstreamAcceptsWork);
        this.engine = requireNonNull(engine, "engine must not be null");
        this.metadataRegistry = requireNonNull(metadataRegistry, "metadataRegistry must not be null");
        this.queueName = requireNonNull(queueName, "queueName must not be null");
        this.pollCommands = metadataRegistry.getAllWorkflowMetadata().stream()
                .map(metadata -> new PollWorkflowTaskCommand(metadata.name(), metadata.lockTimeout()))
                .toList();
    }

    @Override
    List<WorkflowTask> poll(final int limit) {
        return engine.pollWorkflowTasks(queueName, pollCommands, limit);
    }

    @Override
    @SuppressWarnings({"rawtypes", "unchecked"})
    void process(final WorkflowTask task) {
        try (var _ = MDC.putCloseable("workflowName", task.workflowName());
             var _ = MDC.putCloseable("workflowInstanceId", task.workflowInstanceId());
             var _ = MDC.putCloseable("workflowRunId", task.workflowRunId().toString())) {
            final WorkflowMetadata workflowMetadata;
            try {
                workflowMetadata = metadataRegistry.getWorkflowMetadata(task.workflowName());
            } catch (NoSuchElementException e) {
                logger.warn("Workflow does not exist");
                abandon(task);
                return;
            }

            // Hydrate workflow run state from the history.
            final var workflowRunState = new WorkflowRunState(task.workflowRunId(), task.history());
            if (workflowRunState.status() != null && workflowRunState.status().isTerminal()) {
                logger.warn("""
                        Task was scheduled despite the workflow run already being in terminal state {}. \
                        Discarding {} events in the run's inbox.""", workflowRunState.status(), task.inbox().size());

                // TODO: Discard the inbox events without modifying the workflow run.
                // TODO: Consider logging discarded events.
                abandon(task);
                return;
            }

            // Inject a WorkflowTaskStarted event.
            // Its timestamp will be used as deterministic "now" timestamp while processing new events.
            workflowRunState.applyEvent(
                    WorkflowEvent.newBuilder()
                            .setId(-1)
                            .setTimestamp(Timestamps.now())
                            .setWorkflowTaskStarted(WorkflowTaskStarted.getDefaultInstance())
                            .build());

            int eventsAdded = 0;
            for (final WorkflowEvent newEvent : task.inbox()) {
                workflowRunState.applyEvent(newEvent);
                eventsAdded++;

                // Inject a RunStarted event when encountering a RunCreated event.
                // This is mainly to populate the run's startedAt timestamp,
                // so we can differentiate between when a run was created vs.
                // when it was eventually picked up.
                if (newEvent.hasRunCreated()) {
                    workflowRunState.applyEvent(
                            WorkflowEvent.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(Timestamps.now())
                                    .setRunStarted(RunStarted.getDefaultInstance())
                                    .build());
                    eventsAdded++;
                }
            }

            if (eventsAdded == 0) {
                logger.warn("No new events; Abandoning task");
                abandon(task);
                return;
            }

            final var ctx = new WorkflowContextImpl<>(
                    task.workflowRunId(),
                    task.workflowName(),
                    task.workflowVersion(),
                    task.priority(),
                    task.labels(),
                    engine.executorMetadataRegistry(),
                    workflowMetadata.executor(),
                    workflowMetadata.argumentConverter(),
                    workflowMetadata.resultConverter(),
                    workflowRunState.eventHistory(),
                    workflowRunState.newEvents());
            final WorkflowRunExecutionResult executionResult = ctx.execute();

            workflowRunState.setCustomStatus(executionResult.customStatus());
            workflowRunState.processCommands(executionResult.commands());
            if (!workflowRunState.continuedAsNew()) {
                // When continued as new, any pending events have already been deleted,
                // and existing history will be truncated. Adding a WorkflowTaskCompleted
                // event would add no value then.
                workflowRunState.applyEvent(
                        WorkflowEvent.newBuilder()
                                .setId(-1)
                                .setTimestamp(Timestamps.now())
                                .setWorkflowTaskCompleted(WorkflowTaskCompleted.getDefaultInstance())
                                .build());
            }

            engine.onTaskEvent(new WorkflowTaskCompletedEvent(task, workflowRunState));
        }
    }

    @Override
    void abandon(final WorkflowTask task) {
        engine.onTaskEvent(new WorkflowTaskAbandonedEvent(task));
    }

}
