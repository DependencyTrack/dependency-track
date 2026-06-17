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
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityHandle;
import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowHandle;
import org.dependencytrack.dex.api.WorkflowRunBlockedError;
import org.dependencytrack.dex.api.WorkflowRunCanceledError;
import org.dependencytrack.dex.api.WorkflowRunContinuedAsNewError;
import org.dependencytrack.dex.api.WorkflowRunDeterminismError;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.CancellationFailureException;
import org.dependencytrack.dex.api.failure.ChildWorkflowFailureException;
import org.dependencytrack.dex.api.failure.SideEffectFailureException;
import org.dependencytrack.dex.api.payload.PayloadConverter;
import org.dependencytrack.dex.engine.WorkflowCommand.CompleteRunCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.ContinueRunAsNewCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.CreateActivityTaskCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.CreateChildRunCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.CreateTimerCommand;
import org.dependencytrack.dex.engine.WorkflowCommand.RecordSideEffectResultCommand;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskCompleted;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskCreated;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskFailed;
import org.dependencytrack.dex.proto.event.v1.ChildRunCompleted;
import org.dependencytrack.dex.proto.event.v1.ChildRunCreated;
import org.dependencytrack.dex.proto.event.v1.ChildRunFailed;
import org.dependencytrack.dex.proto.event.v1.RunCanceled;
import org.dependencytrack.dex.proto.event.v1.RunCreated;
import org.dependencytrack.dex.proto.event.v1.SideEffectExecuted;
import org.dependencytrack.dex.proto.event.v1.TimerCreated;
import org.dependencytrack.dex.proto.event.v1.TimerElapsed;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.UUID;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;
import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.dex.engine.support.ProtobufUtil.toInstant;
import static org.dependencytrack.dex.engine.support.ProtobufUtil.toProtoTimestamp;

final class WorkflowContextImpl<A, R> implements WorkflowContext<A> {

    private static final Logger LOGGER = LoggerFactory.getLogger(WorkflowContextImpl.class);

    private final UUID runId;
    private final String workflowName;
    private final int workflowVersion;
    private final int priority;
    private final @Nullable Map<String, String> labels;
    private final MetadataRegistry metadataRegistry;
    private final Workflow<A, R> workflow;
    private final PayloadConverter<A> argumentConverter;
    private final PayloadConverter<R> resultConverter;
    private final List<WorkflowEvent> eventHistory;
    private final List<WorkflowEvent> newEvents;
    private final BooleanSupplier hasPendingWorkSupplier;
    private final List<WorkflowEvent> suspendedEvents;
    private final Map<Integer, WorkflowEvent> eventById;
    private final Map<Integer, WorkflowCommand> pendingCommandByEventId;
    private final Map<Integer, AwaitableImpl<?>> pendingAwaitableByEventId;
    private final Map<String, Queue<AwaitableImpl<?>>> pendingAwaitablesByExternalEventId;
    private final Map<String, Queue<WorkflowEvent>> bufferedExternalEvents;
    private final Logger logger;
    private int currentEventIndex;
    private int currentEventId;
    private @Nullable Instant currentTime;
    private @Nullable A argument;
    private boolean isInSideEffect;
    private boolean isReplaying;
    private boolean isSuspended;
    private @Nullable String customStatus;
    private int randomCounter;

    WorkflowContextImpl(
            final UUID runId,
            final String workflowName,
            final int workflowVersion,
            final int priority,
            final @Nullable Map<String, String> labels,
            final MetadataRegistry metadataRegistry,
            final Workflow<A, R> workflow,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final List<WorkflowEvent> eventHistory,
            final List<WorkflowEvent> newEvents,
            final BooleanSupplier hasPendingWorkSupplier) {
        this.runId = runId;
        this.workflowName = workflowName;
        this.workflowVersion = workflowVersion;
        this.priority = priority;
        this.labels = labels;
        this.metadataRegistry = metadataRegistry;
        this.workflow = workflow;
        this.argumentConverter = argumentConverter;
        this.resultConverter = resultConverter;
        this.eventHistory = eventHistory;
        this.newEvents = newEvents;
        this.hasPendingWorkSupplier = hasPendingWorkSupplier;
        this.suspendedEvents = new ArrayList<>();
        this.eventById = new HashMap<>();
        this.pendingCommandByEventId = new HashMap<>();
        this.pendingAwaitableByEventId = new HashMap<>();
        this.pendingAwaitablesByExternalEventId = new HashMap<>();
        this.bufferedExternalEvents = new HashMap<>();
        this.logger = new ReplayAwareLogger(this, LoggerFactory.getLogger(workflow.getClass()));
    }

    @Override
    public UUID runId() {
        return runId;
    }

    @Override
    public String workflowName() {
        return workflowName;
    }

    @Override
    public int workflowVersion() {
        return workflowVersion;
    }

    @Override
    public Map<String, String> labels() {
        return requireNonNullElse(labels, Collections.emptyMap());
    }

    @Override
    public Instant currentTime() {
        if (currentTime == null) {
            throw new IllegalStateException("currentTime was not initialized");
        }

        return currentTime;
    }

    @Override
    public boolean isReplaying() {
        return isReplaying;
    }

    @Override
    public Logger logger() {
        return logger;
    }

    @Override
    public <AA, AR> ActivityHandle<AA, AR> activity(final Class<? extends Activity<AA, AR>> activityClass) {
        final ActivityMetadata<AA, AR> activityMetadata =
                metadataRegistry.getActivityMetadata(activityClass);
        return new ActivityHandleImpl<>(
                this,
                activityMetadata.name(),
                activityMetadata.defaultTaskQueueName(),
                activityMetadata.argumentConverter(),
                activityMetadata.resultConverter());
    }

    @Override
    public <WA, WR> WorkflowHandle<WA, WR> workflow(final Class<? extends Workflow<WA, WR>> workflowClass) {
        final WorkflowMetadata<WA, WR> workflowMetadata =
                metadataRegistry.getWorkflowMetadata(workflowClass);
        return new WorkflowHandleImpl<>(
                this,
                workflowMetadata.name(),
                workflowMetadata.version(),
                workflowMetadata.defaultTaskQueueName(),
                workflowMetadata.argumentConverter(),
                workflowMetadata.resultConverter());
    }

    <AA, AR> Awaitable<AR> callActivity(
            final String name,
            final String taskQueueName,
            final @Nullable AA argument,
            final PayloadConverter<AA> argumentConverter,
            final PayloadConverter<AR> resultConverter,
            final RetryPolicy retryPolicy) {
        requireNotInSideEffect("Activities can not be called from within a side effect");

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId,
                new CreateActivityTaskCommand(
                        eventId,
                        name,
                        taskQueueName,
                        this.priority,
                        argumentConverter.convertToPayload(argument),
                        retryPolicy));

        final var awaitable = new AwaitableImpl<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    <WA, WR> Awaitable<WR> callChildWorkflow(
            String workflowName,
            int workflowVersion,
            @Nullable String workflowInstanceId,
            String taskQueueName,
            @Nullable String concurrencyKey,
            @Nullable WA argument,
            PayloadConverter<WA> argumentConverter,
            PayloadConverter<WR> resultConverter) {
        requireNotInSideEffect("Child workflows can not be called from within a side effect");

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new CreateChildRunCommand(
                eventId,
                workflowName,
                workflowVersion,
                workflowInstanceId,
                taskQueueName,
                concurrencyKey,
                this.priority,
                this.labels,
                argumentConverter.convertToPayload(argument)));

        final var awaitable = new AwaitableImpl<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);
        return awaitable;
    }

    @Override
    public Awaitable<Void> createTimer(final String name, final Duration delay) {
        return createTimerInternal(name, delay);
    }

    private AwaitableImpl<Void> createTimerInternal(final String name, final Duration delay) {
        requireNotInSideEffect("Timers can not be created from within a side effect");

        final int eventId = currentEventId++;
        final int elapsedEventId = currentEventId++;
        pendingCommandByEventId.put(eventId, new CreateTimerCommand(
                eventId, elapsedEventId, name, currentTime.plus(delay)));

        final var awaitable = new AwaitableImpl<>(this, voidConverter());
        pendingAwaitableByEventId.put(elapsedEventId, awaitable);
        return awaitable;
    }

    @Override
    public void setStatus(final @Nullable String status) {
        this.customStatus = status;
    }

    @Override
    public <SA, SR> Awaitable<SR> executeSideEffect(
            final String name,
            final @Nullable SA argument,
            final PayloadConverter<SR> resultConverter,
            final Function<@Nullable SA, @Nullable SR> function) {
        requireNotInSideEffect("Nested side effects are not allowed");
        requireNonNull(name, "name must not be null");
        requireNonNull(resultConverter, "resultConverter must not be null");
        requireNonNull(function, "sideEffectFunction must not be null");

        final int eventId = currentEventId++;

        final var awaitable = new AwaitableImpl<>(this, resultConverter);
        pendingAwaitableByEventId.put(eventId, awaitable);

        if (!isReplaying) {
            try {
                isInSideEffect = true;
                final SR result = function.apply(argument);
                final Payload resultPayload = resultConverter.convertToPayload(result);
                pendingCommandByEventId.put(eventId, new RecordSideEffectResultCommand(
                        name, eventId, resultPayload));
                awaitable.complete(resultPayload);
            } catch (RuntimeException e) {
                awaitable.completeExceptionally(new SideEffectFailureException(name, e));
            } finally {
                isInSideEffect = false;
            }
        }

        return awaitable;
    }

    @Override
    public <ER> Awaitable<ER> waitForExternalEvent(
            final String externalEventId,
            final PayloadConverter<ER> resultConverter,
            final Duration timeout) {
        requireNotInSideEffect("Waiting for external events is not allowed from within a side effect");

        final var awaitable = new AwaitableImpl<>(this, resultConverter);

        final Queue<WorkflowEvent> bufferedEvents = bufferedExternalEvents.get(externalEventId);
        if (bufferedEvents != null && !bufferedEvents.isEmpty()) {
            final WorkflowEvent event = bufferedEvents.poll();
            awaitable.complete(event.getExternalEventReceived().hasPayload()
                    ? event.getExternalEventReceived().getPayload()
                    : null);
            return awaitable;
        }

        if (timeout.equals(Duration.ZERO)) {
            awaitable.cancel("Timed out while waiting for external event");
            return awaitable;
        }

        pendingAwaitablesByExternalEventId.compute(externalEventId, (_, awaitables) -> {
            if (awaitables == null) {
                return new LinkedList<>(List.of(awaitable));
            }

            awaitables.add(awaitable);
            return awaitables;
        });

        createTimerInternal("External event %s wait timeout".formatted(externalEventId), timeout).onComplete(_ -> {
            awaitable.cancel("Timed out while waiting for external event");

            pendingAwaitablesByExternalEventId.computeIfPresent(externalEventId, (_, awaitables) -> {
                awaitables.remove(awaitable);
                if (awaitables.isEmpty()) {
                    return null;
                }

                return awaitables;
            });
        });

        return awaitable;
    }

    @Override
    public void continueAsNew(final ContinueAsNewOptions<A> options) {
        requireNotInSideEffect("continueAsNew is not allowed from within a side effect");
        requireNonNull(options, "options must not be null");
        final boolean hasUnemittedCreateCommand =
                pendingCommandByEventId.values().stream()
                        .anyMatch(cmd -> cmd instanceof CreateActivityTaskCommand
                                || cmd instanceof CreateChildRunCommand
                                || cmd instanceof CreateTimerCommand);
        if (hasPendingWorkSupplier.getAsBoolean() || hasUnemittedCreateCommand) {
            throw new IllegalStateException("""
                    continueAsNew is not allowed while activity tasks, child runs, or timers \
                    are still pending; await or cancel them first""");
        }
        throw new WorkflowRunContinuedAsNewError(
                argumentConverter.convertToPayload(options.argument()));
    }

    WorkflowRunExecutionResult execute() {
        try {
            WorkflowEvent currentEvent;
            while ((currentEvent = processNextEvent()) != null) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Processed {}", DebugFormat.singleLine().toString(currentEvent));
                }
            }
        } catch (WorkflowRunBlockedError e) {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("Blocked");
            }
        } catch (WorkflowRunCanceledError e) {
            cancel(e.getMessage());
        } catch (WorkflowRunContinuedAsNewError e) {
            continueAsNew(e.getArgument());
        } catch (WorkflowRunDeterminismError | Exception e) {
            fail(e);
        }

        final List<WorkflowCommand> commands = !isSuspended
                ? List.copyOf(pendingCommandByEventId.values())
                : Collections.emptyList();

        return new WorkflowRunExecutionResult(commands, customStatus);
    }

    @Nullable
    WorkflowEvent processNextEvent() {
        final WorkflowEvent event = nextEvent();
        if (event == null) {
            return null;
        }

        processEvent(event);
        return event;
    }

    private void processEvent(final WorkflowEvent event) {
        if (event.getId() >= 0) {
            eventById.put(event.getId(), event);
        }

        if (isSuspended && !event.hasRunResumed() && !event.hasRunCanceled()) {
            if (event.hasRunSuspended()) {
                logger().warn("""
                        Encountered RunSuspended event at index {}, \
                        but run is already suspended. Ignoring.""", currentEventIndex);
                return;
            }

            suspendedEvents.add(event);
            return;
        }

        switch (event.getSubjectCase()) {
            case WORKFLOW_TASK_STARTED -> onWorkflowTaskStarted(event);
            case RUN_CREATED -> onRunCreated(event);
            case RUN_STARTED -> onRunStarted(event);
            case RUN_CANCELED -> onRunCanceled(event);
            case RUN_SUSPENDED -> onRunSuspended(event);
            case RUN_RESUMED -> onRunResumed(event);
            case ACTIVITY_TASK_CREATED -> onActivityTaskCreated(event);
            case ACTIVITY_TASK_COMPLETED -> onActivityTaskCompleted(event);
            case ACTIVITY_TASK_FAILED -> onActivityTaskFailed(event);
            case CHILD_RUN_CREATED -> onChildRunCreated(event);
            case CHILD_RUN_COMPLETED -> onChildRunCompleted(event);
            case CHILD_RUN_FAILED -> onChildRunFailed(event);
            case TIMER_CREATED -> onTimerCreated(event);
            case TIMER_ELAPSED -> onTimerElapsed(event);
            case SIDE_EFFECT_EXECUTED -> onSideEffectExecuted(event);
            case EXTERNAL_EVENT_RECEIVED -> onExternalEventReceived(event);
        }
    }

    private @Nullable WorkflowEvent nextEvent() {
        if (currentEventIndex < eventHistory.size()) {
            isReplaying = true;
            return eventHistory.get(currentEventIndex++);
        } else if (currentEventIndex < (eventHistory.size() + newEvents.size())) {
            isReplaying = false;
            return newEvents.get(currentEventIndex++ - eventHistory.size());
        }

        return null;
    }

    private void onWorkflowTaskStarted(final WorkflowEvent event) {
        currentTime = toInstant(event.getTimestamp());
    }

    private void onRunCreated(final WorkflowEvent event) {
        final RunCreated eventSubject = event.getRunCreated();
        logger().debug("Created");

        if (eventSubject.hasArgument()) {
            this.argument = argumentConverter.convertFromPayload(eventSubject.getArgument());
        }
    }

    private void onRunStarted(final WorkflowEvent ignored) {
        logger().debug("Started");

        final R result;
        try {
            result = workflow.execute(this, this.argument);
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new RuntimeException(e);
        }

        complete(result);
    }

    private void onRunCanceled(final WorkflowEvent event) {
        final RunCanceled eventSubject = event.getRunCanceled();
        logger().debug("Canceled with reason: {}", eventSubject.getReason());
        throw new WorkflowRunCanceledError(eventSubject.getReason());
    }

    private void onRunSuspended(final WorkflowEvent ignored) {
        logger().debug("Suspended");
        isSuspended = true;
    }

    private void onRunResumed(final WorkflowEvent ignored) {
        if (!isSuspended) {
            logger().warn("""
                    Encountered RunResumed event at index {}, \
                    but run is not in suspended state. Ignoring.""", currentEventIndex);
            return;
        }

        logger().debug("Resumed");
        isSuspended = false;

        for (final WorkflowEvent event : suspendedEvents) {
            processEvent(event);
        }
    }

    private void onActivityTaskCreated(final WorkflowEvent event) {
        logger().debug("Activity run created for event ID {}", event.getId());
        final ActivityTaskCreated eventSubject = event.getActivityTaskCreated();

        final WorkflowCommand command = pendingCommandByEventId.get(event.getId());
        if (command == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    command was found for it""".formatted(
                    ActivityTaskCreated.class.getSimpleName(),
                    event.getId()));
        } else if (!(command instanceof final CreateActivityTaskCommand concreteCommand)) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but the corresponding \
                    command is of type %s (expected %s)""".formatted(
                    ActivityTaskCreated.class.getSimpleName(),
                    event.getId(),
                    command.getClass().getSimpleName(),
                    CreateActivityTaskCommand.class.getSimpleName()));
        } else if (!Objects.equals(eventSubject.getName(), concreteCommand.name())
                || !Objects.equals(eventSubject.getPriority(), concreteCommand.priority())
                || (eventSubject.hasArgument() && !Objects.equals(eventSubject.getArgument(), concreteCommand.argument()))
                || !Objects.equals(eventSubject.getRetryPolicy(), concreteCommand.retryPolicy().toProto())) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but it does not match \
                    the corresponding %s: event=%s, command=%s""".formatted(
                    ActivityTaskCreated.class.getSimpleName(),
                    event.getId(),
                    CreateActivityTaskCommand.class.getSimpleName(),
                    DebugFormat.singleLine().toString(eventSubject),
                    concreteCommand));
        }

        pendingCommandByEventId.remove(event.getId());
    }

    private void onActivityTaskCompleted(final WorkflowEvent event) {
        final ActivityTaskCompleted eventSubject = event.getActivityTaskCompleted();
        final int createdEventId = eventSubject.getActivityTaskCreatedEventId();
        logger().debug("Activity task completed for event ID {}", createdEventId);

        final WorkflowEvent createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasActivityTaskCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            ActivityTaskCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(createdEventId);
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    ActivityTaskCompleted.class.getSimpleName(),
                    createdEventId));
        }

        awaitable.complete(eventSubject.hasResult() ? eventSubject.getResult() : null);
        pendingAwaitableByEventId.remove(createdEventId);
    }

    private void onActivityTaskFailed(final WorkflowEvent event) {
        final ActivityTaskFailed eventSubject = event.getActivityTaskFailed();
        final int createdEventId = eventSubject.getActivityTaskCreatedEventId();
        logger().debug("Activity task failed for event ID {}", createdEventId);

        final WorkflowEvent createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasActivityTaskCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            ActivityTaskCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(createdEventId);
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    ActivityTaskCompleted.class.getSimpleName(),
                    createdEventId));
        }

        final var exception = new ActivityFailureException(
                createdEvent.getActivityTaskCreated().getName(),
                FailureConverter.toException(eventSubject.getFailure()));

        awaitable.completeExceptionally(exception);
        pendingAwaitableByEventId.remove(createdEventId);
    }

    private void onChildRunCreated(final WorkflowEvent event) {
        logger().debug("Child workflow run created for event ID {}", event.getId());
        final ChildRunCreated eventSubject = event.getChildRunCreated();

        final WorkflowCommand command = pendingCommandByEventId.get(event.getId());
        if (command == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    command was found for it""".formatted(
                    ChildRunCreated.class.getSimpleName(),
                    event.getId()));
        } else if (!(command instanceof final CreateChildRunCommand concreteCommand)) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but the corresponding \
                    command is of type %s (expected %s)""".formatted(
                    ChildRunCreated.class.getSimpleName(),
                    event.getId(),
                    command.getClass().getSimpleName(),
                    CreateChildRunCommand.class.getSimpleName()));
        } else if (!Objects.equals(eventSubject.getWorkflowName(), concreteCommand.workflowName())
                || !Objects.equals(eventSubject.getWorkflowVersion(), concreteCommand.workflowVersion())
                || (eventSubject.hasWorkflowInstanceId()
                && !Objects.equals(eventSubject.getWorkflowInstanceId(), concreteCommand.workflowInstanceId()))
                || !Objects.equals(eventSubject.getPriority(), concreteCommand.priority())
                || (eventSubject.hasConcurrencyKey()
                && !Objects.equals(eventSubject.getConcurrencyKey(), concreteCommand.concurrencyKey()))
                || (eventSubject.getLabelsCount() > 0
                && !Objects.equals(eventSubject.getLabelsMap(), concreteCommand.labels()))
                || (eventSubject.hasArgument()
                && !Objects.equals(eventSubject.getArgument(), concreteCommand.argument()))) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but it does not match \
                    the corresponding %s: event=%s, command=%s""".formatted(
                    ChildRunCreated.class.getSimpleName(),
                    event.getId(),
                    CreateChildRunCommand.class.getSimpleName(),
                    DebugFormat.singleLine().toString(eventSubject),
                    concreteCommand));
        }

        pendingCommandByEventId.remove(event.getId());
    }

    private void onChildRunCompleted(final WorkflowEvent event) {
        final ChildRunCompleted eventSubject = event.getChildRunCompleted();
        final int createdEventId = eventSubject.getChildRunCreatedEventId();
        logger().debug("Child workflow run failed for event ID {}", createdEventId);

        final WorkflowEvent createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasChildRunCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            ChildRunCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(createdEventId);
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    ChildRunCompleted.class.getSimpleName(),
                    createdEventId));
        }

        awaitable.complete(eventSubject.hasResult() ? eventSubject.getResult() : null);
        pendingAwaitableByEventId.remove(createdEventId);
    }

    private void onChildRunFailed(final WorkflowEvent event) {
        final ChildRunFailed eventSubject = event.getChildRunFailed();
        final int createdEventId = eventSubject.getChildRunCreatedEventId();
        logger().debug("Child workflow run failed for event ID {}", createdEventId);

        final WorkflowEvent createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasChildRunCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            ChildRunCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(createdEventId);
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    ChildRunFailed.class.getSimpleName(),
                    createdEventId));
        }

        final var exception = new ChildWorkflowFailureException(
                UUID.fromString(createdEvent.getChildRunCreated().getId()),
                createdEvent.getChildRunCreated().getWorkflowName(),
                createdEvent.getChildRunCreated().getWorkflowVersion(),
                FailureConverter.toException(eventSubject.getFailure()));

        awaitable.completeExceptionally(exception);
        pendingAwaitableByEventId.remove(createdEventId);
    }

    private void onTimerCreated(final WorkflowEvent event) {
        logger().debug("Timer created for event ID {}", event.getId());
        final TimerCreated eventSubject = event.getTimerCreated();

        final WorkflowCommand command = pendingCommandByEventId.get(event.getId());
        if (command == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    command was found for it""".formatted(
                    TimerCreated.class.getSimpleName(),
                    event.getId()));
        } else if (!(command instanceof final CreateTimerCommand concreteCommand)) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but the corresponding \
                    command is of type %s (expected %s)""".formatted(
                    TimerCreated.class.getSimpleName(),
                    event.getId(),
                    command.getClass().getSimpleName(),
                    CreateTimerCommand.class.getSimpleName()));
        } else if (!Objects.equals(eventSubject.getName(), concreteCommand.name())
                || !Objects.equals(eventSubject.getElapseAt(), toProtoTimestamp(concreteCommand.elapseAt()))) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but it does not match \
                    the corresponding %s: event=%s, command=%s""".formatted(
                    TimerCreated.class.getSimpleName(),
                    event.getId(),
                    CreateTimerCommand.class.getSimpleName(),
                    DebugFormat.singleLine().toString(eventSubject),
                    concreteCommand));
        }

        pendingCommandByEventId.remove(event.getId());
    }

    private void onTimerElapsed(final WorkflowEvent event) {
        final TimerElapsed eventSubject = event.getTimerElapsed();
        final int createdEventId = eventSubject.getTimerCreatedEventId();
        logger().debug("Timer elapsed for event ID {}", createdEventId);

        final WorkflowEvent createdEvent = eventById.get(createdEventId);
        if (createdEvent == null || !createdEvent.hasTimerCreated()) {
            throw new WorkflowRunDeterminismError(
                    "Expected event with ID %d to be of type %s, but was: %s".formatted(
                            createdEventId,
                            TimerCreated.class.getSimpleName(),
                            createdEvent != null ?
                                    DebugFormat.singleLine().toString(createdEvent)
                                    : null));
        }

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(event.getId());
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    TimerElapsed.class.getSimpleName(),
                    event.getId()));
        }

        pendingAwaitableByEventId.remove(event.getId());
        awaitable.complete(null);
    }

    private void onSideEffectExecuted(final WorkflowEvent event) {
        final SideEffectExecuted eventSubject = event.getSideEffectExecuted();
        logger().debug("Side effect executed for event ID {}", event.getId());

        final AwaitableImpl<?> awaitable = pendingAwaitableByEventId.get(event.getId());
        if (awaitable == null) {
            throw new WorkflowRunDeterminismError("""
                    Encountered %s event for ID %d, but no corresponding \
                    awaitable was found for it""".formatted(
                    SideEffectExecuted.class.getSimpleName(),
                    event.getId()));
        }

        pendingAwaitableByEventId.remove(event.getId());
        awaitable.complete(eventSubject.hasResult()
                ? eventSubject.getResult()
                : null);
    }

    private void onExternalEventReceived(final WorkflowEvent event) {
        final String externalEventId = event.getExternalEventReceived().getId();
        logger().debug("External event received for ID {}", externalEventId);

        final Payload externalEventContent = event.getExternalEventReceived().hasPayload()
                ? event.getExternalEventReceived().getPayload()
                : null;

        final Queue<AwaitableImpl<?>> pendingAwaitables = pendingAwaitablesByExternalEventId.get(externalEventId);
        if (pendingAwaitables != null) {
            final AwaitableImpl<?> awaitable = pendingAwaitables.poll();
            if (awaitable != null) {
                awaitable.complete(externalEventContent);
            }
            if (pendingAwaitables.isEmpty()) {
                pendingAwaitablesByExternalEventId.remove(externalEventId);
            }

            return;
        }

        bufferedExternalEvents.compute(externalEventId, (_, awaitables) -> {
            if (awaitables == null) {
                return new LinkedList<>(List.of(event));
            }

            awaitables.add(event);
            return awaitables;
        });
    }

    private void cancel(final String reason) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} canceled", workflowName, runId);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(
                eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.CANCELLED,
                        customStatus,
                        /* result */ null,
                        FailureConverter.toFailure(new CancellationFailureException(reason))));

        isSuspended = false;
    }

    private void complete(final @Nullable R result) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} completed with result {}", workflowName, runId, result);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(
                eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.COMPLETED,
                        customStatus,
                        resultConverter.convertToPayload(result),
                        /* failure */ null));
    }

    private void continueAsNew(final @Nullable Payload argument) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} continued as new with argument {}", workflowName, runId, argument);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(
                eventId,
                new ContinueRunAsNewCommand(eventId, argument));
    }

    private void fail(final Throwable exception) {
        if (logger().isDebugEnabled()) {
            logger().debug("Workflow run {}/{} failed", workflowName, runId, exception);
        }

        final int eventId = currentEventId++;
        pendingCommandByEventId.put(
                eventId,
                new CompleteRunCommand(
                        eventId,
                        WorkflowRunStatus.FAILED,
                        customStatus,
                        /* result */ null,
                        FailureConverter.toFailure(exception)));
    }

    private void requireNotInSideEffect(final String message) {
        if (isInSideEffect) {
            throw new IllegalStateException(message);
        }
    }

}
