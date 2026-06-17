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

import com.google.protobuf.DebugFormat;
import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.dex.engine.WorkflowCommand.CompleteRunCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.ContinueRunAsNewCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.CreateActivityTaskCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.CreateChildRunCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.CreateTimerCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.RecordSideEffectResultCommand;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskCreated;
import org.dependencytrack.dex.proto.event.v1.ChildRunCompleted;
import org.dependencytrack.dex.proto.event.v1.ChildRunCreated;
import org.dependencytrack.dex.proto.event.v1.ChildRunFailed;
import org.dependencytrack.dex.proto.event.v1.RunCompleted;
import org.dependencytrack.dex.proto.event.v1.RunCreated;
import org.dependencytrack.dex.proto.event.v1.SideEffectExecuted;
import org.dependencytrack.dex.proto.event.v1.TimerCreated;
import org.dependencytrack.dex.proto.event.v1.TimerElapsed;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.dex.proto.failure.v1.Failure;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.SequencedCollection;
import java.util.Set;
import java.util.UUID;

import static com.fasterxml.uuid.Generators.timeBasedEpochRandomGenerator;
import static org.dependencytrack.dex.engine.support.ProtobufUtil.toInstant;
import static org.dependencytrack.dex.engine.support.ProtobufUtil.toProtoTimestamp;

/**
 * State of a workflow run.
 * <p>
 * The state is event-sourced by applying {@link WorkflowEvent}s,
 * and modified via processing of {@link WorkflowCommand}s.
 * <p>
 * This merely implements a state machine and does not
 * perform any I/O or otherwise mutating operations.
 */
final class WorkflowRunState {

    private final UUID id;
    private @Nullable UUID parentId;
    private @Nullable String workflowName;
    private @Nullable Integer workflowVersion;
    private @Nullable String workflowInstanceId;
    private @Nullable String taskQueueName;
    private @Nullable String concurrencyKey;
    private final List<WorkflowEvent> eventHistory;
    private final List<WorkflowEvent> newEvents;
    private final List<WorkflowEvent> pendingActivityTaskCreatedEvents;
    private final List<WorkflowMessage> pendingMessages;
    private final Map<Integer, UUID> pendingChildRunIdByEventId;
    private final Map<Integer, ActivityTaskId> pendingActivityTaskIdByEventId;
    private final Set<Integer> pendingTimerCreatedEventIds;
    private @Nullable WorkflowEvent createdEvent;
    private @Nullable WorkflowEvent startedEvent;
    private @Nullable WorkflowEvent completedEvent;
    private @Nullable Payload argument;
    private @Nullable Payload result;
    private @Nullable Failure failure;
    private @Nullable WorkflowRunStatus status;
    private @Nullable String customStatus;
    private @Nullable Integer priority;
    private @Nullable Map<String, String> labels;
    private @Nullable Instant createdAt;
    private @Nullable Instant updatedAt;
    private @Nullable Instant startedAt;
    private @Nullable Instant completedAt;
    private boolean continuedAsNew;

    WorkflowRunState(
            final UUID id,
            final List<WorkflowEvent> eventHistory) {
        this.id = id;
        this.eventHistory = new ArrayList<>(eventHistory.size());
        this.newEvents = new ArrayList<>();
        this.pendingActivityTaskCreatedEvents = new ArrayList<>();
        this.pendingMessages = new ArrayList<>();
        this.pendingChildRunIdByEventId = new HashMap<>();
        this.pendingActivityTaskIdByEventId = new HashMap<>();
        this.pendingTimerCreatedEventIds = new HashSet<>();

        for (final WorkflowEvent event : eventHistory) {
            applyEvent(event, /* isNew */ false);
        }
    }

    UUID id() {
        return id;
    }

    @Nullable
    UUID parentId() {
        return parentId;
    }

    @Nullable
    String workflowName() {
        return workflowName;
    }

    @Nullable
    Integer workflowVersion() {
        return workflowVersion;
    }

    @Nullable
    String workflowInstanceId() {
        return workflowInstanceId;
    }

    @Nullable
    String taskQueueName() {
        return taskQueueName;
    }

    @Nullable
    String concurrencyKey() {
        return concurrencyKey;
    }

    List<WorkflowEvent> eventHistory() {
        return eventHistory;
    }

    List<WorkflowEvent> newEvents() {
        return newEvents;
    }

    List<WorkflowEvent> pendingActivityTaskCreatedEvents() {
        return pendingActivityTaskCreatedEvents;
    }

    List<WorkflowMessage> pendingMessages() {
        return pendingMessages;
    }

    /**
     * @return IDs of child runs that were created, but for which no completion
     * event has been recorded yet.
     */
    Collection<UUID> pendingChildRunIds() {
        return pendingChildRunIdByEventId.values();
    }

    /**
     * @return IDs of activity tasks that were created, but for which no completion
     * event has been recorded yet.
     */
    Collection<ActivityTaskId> pendingActivityTaskIds() {
        return pendingActivityTaskIdByEventId.values();
    }

    /**
     * @return IDs of {@code TimerCreated} events for which no corresponding
     * {@code TimerElapsed} event has been recorded yet.
     */
    Set<Integer> pendingTimerCreatedEventIds() {
        return pendingTimerCreatedEventIds;
    }

    @Nullable
    WorkflowRunStatus status() {
        return status;
    }

    @Nullable
    String customStatus() {
        return customStatus;
    }

    void setCustomStatus(final @Nullable String customStatus) {
        this.customStatus = customStatus;
    }

    @Nullable
    Integer priority() {
        return priority;
    }

    @Nullable
    Map<String, String> labels() {
        return labels;
    }

    @Nullable
    Payload argument() {
        return argument;
    }

    @Nullable
    Payload result() {
        return result;
    }

    @Nullable
    Failure failure() {
        return failure;
    }

    @Nullable
    Instant createdAt() {
        return createdAt;
    }

    @Nullable
    Instant updatedAt() {
        return updatedAt;
    }

    @Nullable
    Instant startedAt() {
        return startedAt;
    }

    @Nullable
    Instant completedAt() {
        return completedAt;
    }

    boolean continuedAsNew() {
        return continuedAsNew;
    }

    void applyEvent(final WorkflowEvent event) {
        applyEvent(event, /* isNew */ true);
    }

    private void applyEvent(final WorkflowEvent event, final boolean isNew) {
        switch (event.getSubjectCase()) {
            case RUN_CREATED -> {
                if (createdEvent != null) {
                    final String previousEventStr = DebugFormat.singleLine().toString(createdEvent);
                    final String nextEventStr = DebugFormat.singleLine().toString(event);

                    throw new IllegalStateException(
                            "%s/%s: Duplicate RunCreated event; Previous event is: %s; New event is: %s".formatted(
                                    this.workflowName, this.id, previousEventStr, nextEventStr));
                }
                parentId = event.getRunCreated().hasParentRun()
                        ? UUID.fromString(event.getRunCreated().getParentRun().getId())
                        : null;
                workflowName = event.getRunCreated().getWorkflowName();
                workflowVersion = event.getRunCreated().getWorkflowVersion();
                workflowInstanceId = event.getRunCreated().hasWorkflowInstanceId()
                        ? event.getRunCreated().getWorkflowInstanceId()
                        : null;
                taskQueueName = event.getRunCreated().getTaskQueueName();
                concurrencyKey = event.getRunCreated().hasConcurrencyKey()
                        ? event.getRunCreated().getConcurrencyKey()
                        : null;
                setStatus(WorkflowRunStatus.CREATED);
                createdEvent = event;
                argument = event.getRunCreated().hasArgument()
                        ? event.getRunCreated().getArgument()
                        : null;
                priority = event.getRunCreated().getPriority();
                labels = event.getRunCreated().getLabelsCount() > 0
                        ? event.getRunCreated().getLabelsMap()
                        : null;
                createdAt = toInstant(event.getTimestamp());
            }
            case RUN_STARTED -> {
                if (startedEvent != null) {
                    final String previousEventStr = DebugFormat.singleLine().toString(startedEvent);
                    final String nextEventStr = DebugFormat.singleLine().toString(event);

                    throw new IllegalStateException(
                            "%s/%s: Duplicate RunStarted event; Previous event is: %s; New event is: %s".formatted(
                                    this.workflowName, this.id, previousEventStr, nextEventStr));
                }
                startedEvent = event;
                setStatus(WorkflowRunStatus.RUNNING);
                startedAt = toInstant(event.getTimestamp());
            }
            case RUN_COMPLETED -> {
                if (completedEvent != null) {
                    final String previousEventStr = DebugFormat.singleLine().toString(completedEvent);
                    final String nextEventStr = DebugFormat.singleLine().toString(event);

                    throw new IllegalStateException(
                            "%s/%s: Duplicate RunCompleted event; Previous event is: %s; Next event is: %s".formatted(
                                    this.workflowName, this.id, previousEventStr, nextEventStr));
                }
                completedEvent = event;
                setStatus(WorkflowRunStatus.fromProto(completedEvent.getRunCompleted().getStatus()));
                customStatus = event.getRunCompleted().hasCustomStatus()
                        ? event.getRunCompleted().getCustomStatus()
                        : null;
                result = event.getRunCompleted().hasResult()
                        ? event.getRunCompleted().getResult()
                        : null;
                failure = event.getRunCompleted().hasFailure()
                        ? event.getRunCompleted().getFailure()
                        : null;
                completedAt = toInstant(event.getTimestamp());
            }
            case RUN_SUSPENDED -> setStatus(WorkflowRunStatus.SUSPENDED);
            case RUN_RESUMED -> setStatus(WorkflowRunStatus.RUNNING);
            case ACTIVITY_TASK_CREATED -> {
                pendingActivityTaskIdByEventId.put(
                        event.getId(),
                        new ActivityTaskId(
                                event.getActivityTaskCreated().getQueueName(),
                                this.id,
                                event.getId()));
            }
            case ACTIVITY_TASK_COMPLETED -> {
                final int createdEventId = event.getActivityTaskCompleted().getActivityTaskCreatedEventId();
                pendingActivityTaskIdByEventId.remove(createdEventId);
            }
            case ACTIVITY_TASK_FAILED -> {
                final int createdEventId = event.getActivityTaskFailed().getActivityTaskCreatedEventId();
                pendingActivityTaskIdByEventId.remove(createdEventId);
            }
            case CHILD_RUN_CREATED -> {
                final String runId = event.getChildRunCreated().getId();
                pendingChildRunIdByEventId.put(event.getId(), UUID.fromString(runId));
            }
            case CHILD_RUN_COMPLETED -> {
                final int createdEventId = event.getChildRunCompleted().getChildRunCreatedEventId();
                pendingChildRunIdByEventId.remove(createdEventId);
            }
            case CHILD_RUN_FAILED -> {
                final int createdEventId = event.getChildRunFailed().getChildRunCreatedEventId();
                pendingChildRunIdByEventId.remove(createdEventId);
            }
            case TIMER_CREATED -> pendingTimerCreatedEventIds.add(event.getId());
            case TIMER_ELAPSED -> {
                final int createdEventId = event.getTimerElapsed().getTimerCreatedEventId();
                pendingTimerCreatedEventIds.remove(createdEventId);
            }
        }

        if (isNew) {
            newEvents.add(event);
        } else {
            eventHistory.add(event);
        }

        updatedAt = toInstant(event.getTimestamp());
    }

    void processCommands(final SequencedCollection<WorkflowCommand> commands) {
        for (final WorkflowCommand command : commands) {
            processCommand(command);
        }
    }

    private void processCommand(final WorkflowCommand command) {
        switch (command) {
            case CompleteRunCommand it -> processCompleteRunCommand(it);
            case ContinueRunAsNewCommand it -> processContinueAsNewCommand(it);
            case RecordSideEffectResultCommand it -> processRecordSideEffectResultCommand(it);
            case CreateActivityTaskCommand it -> processCreateActivityTaskCommand(it);
            case CreateChildRunCommand it -> processCreateChildRunCommand(it);
            case CreateTimerCommand it -> processCreateTimerCommand(it);
            default -> throw new IllegalStateException("Unexpected command: " + command);
        }
    }

    private void processCompleteRunCommand(final CompleteRunCommand command) {
        // If this is a sub-workflow run, ensure the parent run is informed about the outcome.
        if (createdEvent.getRunCreated().hasParentRun()) {
            final RunCreated.ParentRun parentRun = createdEvent.getRunCreated().getParentRun();
            final var parentRunId = UUID.fromString(parentRun.getId());

            final var childRunEventBuilder = WorkflowEvent.newBuilder()
                    .setId(-1)
                    .setTimestamp(Timestamps.now());
            if (command.status() == WorkflowRunStatus.COMPLETED) {
                final var childRunCompletedBuilder = ChildRunCompleted.newBuilder()
                        .setChildRunCreatedEventId(parentRun.getChildRunCreatedEventId());
                if (command.result() != null) {
                    childRunCompletedBuilder.setResult(command.result());
                }
                childRunEventBuilder.setChildRunCompleted(
                        childRunCompletedBuilder.build());
            } else if (command.status() == WorkflowRunStatus.CANCELLED || command.status() == WorkflowRunStatus.FAILED) {
                final var childRunFailedBuilder = ChildRunFailed.newBuilder()
                        .setChildRunCreatedEventId(parentRun.getChildRunCreatedEventId());
                if (command.failure() != null) {
                    childRunFailedBuilder.setFailure(command.failure());
                }
                childRunEventBuilder.setChildRunFailed(
                        childRunFailedBuilder.build());
            } else {
                throw new IllegalStateException("Unexpected command status: " + command.status());
            }

            pendingMessages.add(new WorkflowMessage(parentRunId, childRunEventBuilder.build()));
        }

        // Record completion of the run in the history.
        final var subjectBuilder = RunCompleted.newBuilder()
                .setStatus(command.status().toProto());
        if (command.customStatus() != null) {
            subjectBuilder.setCustomStatus(command.customStatus());
        }
        if (command.result() != null) {
            subjectBuilder.setResult(command.result());
        }
        if (command.failure() != null) {
            subjectBuilder.setFailure(command.failure());
        }
        applyEvent(
                WorkflowEvent.newBuilder()
                        .setId(command.eventId())
                        .setTimestamp(Timestamps.now())
                        .setRunCompleted(subjectBuilder.build())
                        .build(),
                /* isNew */ true);
    }

    private void processContinueAsNewCommand(final ContinueRunAsNewCommand command) {
        final var newRunCreatedBuilder = RunCreated.newBuilder()
                .setWorkflowName(this.workflowName)
                .setWorkflowVersion(this.workflowVersion)
                .setTaskQueueName(this.taskQueueName)
                .setPriority(this.priority);
        if (command.argument() != null) {
            newRunCreatedBuilder.setArgument(command.argument());
        }
        if (this.workflowInstanceId != null) {
            newRunCreatedBuilder.setWorkflowInstanceId(this.workflowInstanceId);
        }
        if (this.concurrencyKey != null) {
            newRunCreatedBuilder.setConcurrencyKey(this.concurrencyKey);
        }
        if (this.labels != null && !this.labels.isEmpty()) {
            newRunCreatedBuilder.putAllLabels(this.labels);
        }
        if (this.createdEvent.getRunCreated().hasParentRun()) {
            newRunCreatedBuilder.setParentRun(this.createdEvent.getRunCreated().getParentRun());
        }

        this.continuedAsNew = true;
        this.eventHistory.clear();
        this.newEvents.clear();
        this.pendingActivityTaskCreatedEvents.clear();
        this.pendingMessages.clear();
        this.pendingMessages.add(
                new WorkflowMessage(
                        this.id,
                        WorkflowEvent.newBuilder()
                                .setId(-1)
                                .setTimestamp(Timestamps.now())
                                .setRunCreated(newRunCreatedBuilder)
                                .build()));
    }

    private void processRecordSideEffectResultCommand(final RecordSideEffectResultCommand command) {
        final var subjectBuilder = SideEffectExecuted.newBuilder()
                .setName(command.name());
        if (command.result() != null) {
            subjectBuilder.setResult(command.result());
        }

        applyEvent(
                WorkflowEvent.newBuilder()
                        .setId(command.eventId())
                        .setTimestamp(Timestamps.now())
                        .setSideEffectExecuted(subjectBuilder.build())
                        .build());
    }

    private void processCreateActivityTaskCommand(final CreateActivityTaskCommand command) {
        final var subjectBuilder = ActivityTaskCreated.newBuilder()
                .setName(command.name())
                .setQueueName(command.queueName())
                .setPriority(command.priority())
                .setRetryPolicy(command.retryPolicy().toProto());
        if (command.argument() != null) {
            subjectBuilder.setArgument(command.argument());
        }

        final var activityTaskCreatedEvent = WorkflowEvent.newBuilder()
                .setId(command.eventId())
                .setTimestamp(Timestamps.now())
                .setActivityTaskCreated(subjectBuilder.build())
                .build();
        applyEvent(activityTaskCreatedEvent, /* isNew */ true);
        pendingActivityTaskCreatedEvents.add(activityTaskCreatedEvent);
    }

    private void processCreateChildRunCommand(final CreateChildRunCommand command) {
        final UUID childRunId = timeBasedEpochRandomGenerator().generate();


        final var childRunCreatedBuilder = ChildRunCreated.newBuilder()
                .setId(childRunId.toString())
                .setWorkflowName(command.workflowName())
                .setWorkflowVersion(command.workflowVersion())
                .setTaskQueueName(command.taskQueueName())
                .setPriority(command.priority());
        final var runCreatedBuilder = RunCreated.newBuilder()
                .setWorkflowName(command.workflowName())
                .setWorkflowVersion(command.workflowVersion())
                .setTaskQueueName(command.taskQueueName())
                .setPriority(command.priority());
        if (command.workflowInstanceId() != null) {
            childRunCreatedBuilder.setWorkflowInstanceId(command.workflowInstanceId());
            runCreatedBuilder.setWorkflowInstanceId(command.workflowInstanceId());
        }
        if (command.concurrencyKey() != null) {
            childRunCreatedBuilder.setConcurrencyKey(command.concurrencyKey());
            runCreatedBuilder.setConcurrencyKey(command.concurrencyKey());
        }
        if (command.labels() != null && !command.labels().isEmpty()) {
            childRunCreatedBuilder.putAllLabels(command.labels());
            runCreatedBuilder.putAllLabels(command.labels());
        }
        if (command.argument() != null) {
            childRunCreatedBuilder.setArgument(command.argument());
            runCreatedBuilder.setArgument(command.argument());
        }

        final var parentRunBuilder = RunCreated.ParentRun.newBuilder()
                .setChildRunCreatedEventId(command.eventId())
                .setId(this.id.toString())
                .setWorkflowName(this.workflowName)
                .setWorkflowVersion(this.workflowVersion);
        if (this.workflowInstanceId != null) {
            parentRunBuilder.setWorkflowInstanceId(this.workflowInstanceId);
        }
        runCreatedBuilder.setParentRun(parentRunBuilder.build());

        applyEvent(
                WorkflowEvent.newBuilder()
                        .setId(command.eventId())
                        .setTimestamp(Timestamps.now())
                        .setChildRunCreated(childRunCreatedBuilder.build())
                        .build(),
                /* isNew */ true);

        pendingMessages.add(
                new WorkflowMessage(
                        childRunId,
                        WorkflowEvent.newBuilder()
                                .setId(-1)
                                .setTimestamp(Timestamps.now())
                                .setRunCreated(runCreatedBuilder.build())
                                .build()));
    }

    private void processCreateTimerCommand(final CreateTimerCommand command) {
        final Timestamp elapseAt = toProtoTimestamp(command.elapseAt());

        applyEvent(
                WorkflowEvent.newBuilder()
                        .setId(command.eventId())
                        .setTimestamp(Timestamps.now())
                        .setTimerCreated(TimerCreated.newBuilder()
                                .setName(command.name())
                                .setElapseAt(elapseAt)
                                .build())
                        .build(),
                /* isNew */ true);

        pendingMessages.add(
                new WorkflowMessage(
                        this.id,
                        WorkflowEvent.newBuilder()
                                .setId(command.elapsedEventId())
                                .setTimestamp(elapseAt)
                                .setTimerElapsed(
                                        TimerElapsed.newBuilder()
                                                .setTimerCreatedEventId(command.eventId())
                                                .build())
                                .build(),
                        command.elapseAt()));
    }

    private void setStatus(final WorkflowRunStatus newStatus) {
        if (this.status == null || this.status.canTransitionTo(newStatus)) {
            this.status = newStatus;
            return;
        }

        throw new IllegalStateException(
                "Can not transition from state %s to %s".formatted(this.status, newStatus));
    }

}
