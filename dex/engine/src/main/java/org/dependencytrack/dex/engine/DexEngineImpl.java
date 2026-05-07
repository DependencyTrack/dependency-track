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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.protobuf.util.Timestamps;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.PageIterator;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.failure.InternalFailureException;
import org.dependencytrack.dex.api.payload.PayloadConverter;
import org.dependencytrack.dex.engine.TaskEvent.ActivityTaskAbandonedEvent;
import org.dependencytrack.dex.engine.TaskEvent.ActivityTaskCompletedEvent;
import org.dependencytrack.dex.engine.TaskEvent.ActivityTaskFailedEvent;
import org.dependencytrack.dex.engine.TaskEvent.WorkflowTaskAbandonedEvent;
import org.dependencytrack.dex.engine.TaskEvent.WorkflowTaskCompletedEvent;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.ExternalEvent;
import org.dependencytrack.dex.engine.api.TaskQueue;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunHistoryEntry;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.event.DexEngineEvent;
import org.dependencytrack.dex.engine.api.event.DexEngineEventListener;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEventListener;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ExistsWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.engine.api.request.UpdateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.response.CreateWorkflowRunResponse;
import org.dependencytrack.dex.engine.persistence.ActivityDao;
import org.dependencytrack.dex.engine.persistence.WorkflowDao;
import org.dependencytrack.dex.engine.persistence.WorkflowRunDao;
import org.dependencytrack.dex.engine.persistence.command.CreateActivityTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunCommand;
import org.dependencytrack.dex.engine.persistence.command.CreateWorkflowRunHistoryEntryCommand;
import org.dependencytrack.dex.engine.persistence.command.DeleteWorkflowMessagesCommand;
import org.dependencytrack.dex.engine.persistence.command.PollActivityTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.PollWorkflowTaskCommand;
import org.dependencytrack.dex.engine.persistence.command.ScheduleActivityTaskRetryCommand;
import org.dependencytrack.dex.engine.persistence.command.UpdateAndUnlockRunCommand;
import org.dependencytrack.dex.engine.persistence.jdbi.JdbiFactory;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowEvents;
import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowTask;
import org.dependencytrack.dex.engine.persistence.request.GetWorkflowRunHistoryRequest;
import org.dependencytrack.dex.engine.support.Buffer;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskCompleted;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskFailed;
import org.dependencytrack.dex.proto.event.v1.ChildRunFailed;
import org.dependencytrack.dex.proto.event.v1.ExternalEventReceived;
import org.dependencytrack.dex.proto.event.v1.RunCanceled;
import org.dependencytrack.dex.proto.event.v1.RunCreated;
import org.dependencytrack.dex.proto.event.v1.RunResumed;
import org.dependencytrack.dex.proto.event.v1.RunSuspended;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.statement.Update;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

import static com.fasterxml.uuid.Generators.timeBasedEpochRandomGenerator;
import static java.util.Objects.requireNonNull;
import static org.dependencytrack.dex.engine.support.ProtobufUtil.toInstant;
import static org.dependencytrack.dex.engine.support.ProtobufUtil.toProtoTimestamp;

final class DexEngineImpl implements DexEngine {

    enum Status {

        CREATED(1, 3), // 0
        STARTING(2),   // 1
        RUNNING(3),    // 2
        STOPPING(4),   // 3
        STOPPED(1);    // 4

        private final Set<Integer> allowedTransitions;

        Status(Integer... allowedTransitions) {
            this.allowedTransitions = Set.of(allowedTransitions);
        }

        private boolean canTransitionTo(Status newStatus) {
            return allowedTransitions.contains(newStatus.ordinal());
        }

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(DexEngineImpl.class);

    private final DexEngineConfig config;
    private final Jdbi jdbi;
    private final ReentrantLock statusLock = new ReentrantLock();
    private final MetadataRegistry metadataRegistry = new MetadataRegistry();
    private final Map<String, TaskWorker> taskWorkerByName = new HashMap<>();
    private final Map<String, TaskWorker> workflowWorkerByQueue = new HashMap<>();
    private final Map<String, TaskWorker> activityWorkerByQueue = new HashMap<>();
    private final List<WorkflowRunsCompletedEventListener> runsCompletedEventListeners = new ArrayList<>();
    private final MeterProvider<Counter> runsCreatedCounter;
    private final MeterProvider<Counter> runsCompletedCounter;

    private volatile Status status = Status.CREATED;
    private @Nullable DexEngineLeaderElection leaderElection;
    private @Nullable DexEngineMetricsCollector metricsCollector;
    private @Nullable WorkflowTaskScheduler workflowTaskScheduler;
    private @Nullable ActivityTaskScheduler activityTaskScheduler;
    private @Nullable ExecutorService eventListenerExecutor;
    private @Nullable Buffer<ExternalEvent> externalEventBuffer;
    private @Nullable Buffer<TaskEvent> taskEventBuffer;
    private @Nullable Buffer<ActivityTaskHeartbeat> activityTaskHeartbeatBuffer;
    private @Nullable MaintenanceWorker maintenanceWorker;
    private @Nullable Cache<WorkflowRunHistoryCacheKey, CachedWorkflowRunHistory> runHistoryCache;

    DexEngineImpl(DexEngineConfig config) {
        this.config = requireNonNull(config);
        this.jdbi = JdbiFactory.create(config.dataSource(), config.pageTokenEncoder());
        this.runsCreatedCounter = Counter
                .builder("dt.dex.engine.runs.created")
                .withRegistry(config.metrics().meterRegistry());
        this.runsCompletedCounter = Counter
                .builder("dt.dex.engine.runs.completed")
                .withRegistry(config.metrics().meterRegistry());
    }

    @Override
    public void start() {
        setStatus(Status.STARTING);
        LOGGER.debug("Starting");

        Gauge
                .builder("dt.dex.engine.info", () -> 1)
                .tag("instanceId", config.instanceId())
                .register(config.metrics().meterRegistry());

        LOGGER.debug("Initializing history cache");
        final var runHistoryCacheBuilder = Caffeine.newBuilder()
                .maximumSize(config.runHistoryCache().maxSize())
                .recordStats();
        if (config.runHistoryCache().evictAfterAccess() != null) {
            runHistoryCacheBuilder.expireAfterAccess(config.runHistoryCache().evictAfterAccess());
        }
        runHistoryCache = runHistoryCacheBuilder.build();
        new CaffeineCacheMetrics<>(runHistoryCache, "DexEngine-RunHistoryCache", null)
                .bindTo(config.metrics().meterRegistry());

        LOGGER.debug("Registering default event listeners");
        runsCompletedEventListeners.add(this::invalidateCompletedRunsHistoryCache);
        runsCompletedEventListeners.add(this::recordCompletedRunsMetrics);

        LOGGER.debug("Starting event listener executor");
        eventListenerExecutor = Executors.newSingleThreadExecutor(
                Thread.ofPlatform()
                        .name("DexEngine-EventListener")
                        .factory());

        if (config.leaderElection().isEnabled()) {
            LOGGER.debug("Starting leader election");
            leaderElection = new DexEngineLeaderElection(
                    config.instanceId(),
                    jdbi,
                    config.leaderElection().leaseDuration(),
                    config.leaderElection().leaseCheckInterval(),
                    config.metrics().meterRegistry());
            leaderElection.start();
        } else {
            LOGGER.debug("Not starting leader election because it is disabled");
        }

        if (config.metrics().isCollectorEnabled()) {
            LOGGER.debug("Starting metrics collector");
            metricsCollector = new DexEngineMetricsCollector(
                    jdbi,
                    config.metrics().collectorInitialDelay(),
                    config.metrics().collectorInterval(),
                    config.metrics().meterRegistry());
            metricsCollector.start();
        } else {
            LOGGER.debug("Not starting metrics collector because it is disabled");
        }

        if (config.leaderElection().isEnabled()) {
            LOGGER.debug("Starting workflow task scheduler");
            workflowTaskScheduler = new WorkflowTaskScheduler(
                    jdbi,
                    leaderElection::isLeader,
                    config.metrics().meterRegistry(),
                    config.workflowTaskScheduler().pollInterval(),
                    config.workflowTaskScheduler().pollBackoffFunction(),
                    queueName -> {
                        final TaskWorker worker = workflowWorkerByQueue.get(queueName);
                        if (worker != null) {
                            worker.nudge();
                        }
                    });
            workflowTaskScheduler.start();

            LOGGER.debug("Starting activity task scheduler");
            activityTaskScheduler = new ActivityTaskScheduler(
                    jdbi,
                    leaderElection::isLeader,
                    config.metrics().meterRegistry(),
                    config.activityTaskScheduler().pollInterval(),
                    config.activityTaskScheduler().pollBackoffFunction(),
                    queueName -> {
                        final TaskWorker worker = activityWorkerByQueue.get(queueName);
                        if (worker != null) {
                            worker.nudge();
                        }
                    });
            activityTaskScheduler.start();
        } else {
            LOGGER.debug("Not starting task schedulers because leader election is disabled");
        }

        LOGGER.debug("Starting external event buffer");
        externalEventBuffer = new Buffer<>(
                "external-event",
                this::flushExternalEvents,
                config.externalEventBuffer().flushInterval(),
                config.externalEventBuffer().maxBatchSize(),
                config.metrics().meterRegistry());
        externalEventBuffer.start();

        // The buffer's flush interval should be long enough to allow
        // for more than one task result to be included, but short enough
        // to not block task execution unnecessarily. In a worst-case scenario,
        // task workers can be blocked for an entire flush interval.
        // TODO: Separate buffer for workflow task events from buffer for activity task events?
        //  Workflow tasks usually complete a lot faster than activity tasks.
        LOGGER.debug("Starting task event buffer");
        taskEventBuffer = new Buffer<>(
                "task-event",
                this::flushTaskEvents,
                config.taskEventBuffer().flushInterval(),
                config.taskEventBuffer().maxBatchSize(),
                config.metrics().meterRegistry());
        taskEventBuffer.start();

        LOGGER.debug("Starting activity task heartbeat buffer");
        activityTaskHeartbeatBuffer = new Buffer<>(
                "activity-task-heartbeat",
                this::processActivityTaskHeartbeats,
                config.activityTaskHeartbeatBuffer().flushInterval(),
                config.activityTaskHeartbeatBuffer().maxBatchSize(),
                config.metrics().meterRegistry());
        activityTaskHeartbeatBuffer.start();

        if (config.leaderElection().isEnabled()) {
            LOGGER.debug("Starting maintenance worker");
            maintenanceWorker = new MaintenanceWorker(
                    jdbi,
                    leaderElection::isLeader,
                    config.maintenance().runRetentionDuration(),
                    config.maintenance().runDeletionBatchSize(),
                    config.maintenance().workerInitialDelay(),
                    config.maintenance().workerInterval());
            maintenanceWorker.start();
        } else {
            LOGGER.debug("Not starting maintenance worker because leader election is disabled");
        }

        for (final Map.Entry<String, TaskWorker> entry : taskWorkerByName.entrySet()) {
            LOGGER.debug("Starting task worker {}", entry.getKey());
            entry.getValue().start();
        }

        setStatus(Status.RUNNING);
        LOGGER.debug("Started");
    }

    @Override
    public void close() throws IOException {
        if (status == Status.STOPPED) {
            return;
        }

        setStatus(Status.STOPPING);
        LOGGER.debug("Stopping");

        if (maintenanceWorker != null) {
            LOGGER.debug("Waiting for maintenance worker to stop");
            maintenanceWorker.close();
            maintenanceWorker = null;
        }

        if (activityTaskScheduler != null) {
            LOGGER.debug("Waiting for activity task scheduler to stop");
            activityTaskScheduler.close();
            activityTaskScheduler = null;
        }

        if (workflowTaskScheduler != null) {
            LOGGER.debug("Waiting for workflow task scheduler to stop");
            workflowTaskScheduler.close();
            workflowTaskScheduler = null;
        }

        if (!taskWorkerByName.isEmpty()) {
            for (final Map.Entry<String, TaskWorker> entry : taskWorkerByName.entrySet()) {
                LOGGER.debug("Waiting for task worker {} to stop", entry.getKey());
                entry.getValue().close();
            }
            taskWorkerByName.clear();
            workflowWorkerByQueue.clear();
            activityWorkerByQueue.clear();
        }

        if (externalEventBuffer != null) {
            LOGGER.debug("Waiting for external event buffer to stop");
            externalEventBuffer.close();
            externalEventBuffer = null;
        }

        if (activityTaskHeartbeatBuffer != null) {
            LOGGER.debug("Waiting for activity task heartbeat buffer to stop");
            activityTaskHeartbeatBuffer.close();
            activityTaskHeartbeatBuffer = null;
        }

        if (taskEventBuffer != null) {
            LOGGER.debug("Waiting for task event buffer to stop");
            taskEventBuffer.close();
            taskEventBuffer = null;
        }

        if (metricsCollector != null) {
            LOGGER.debug("Waiting for metrics collector to stop");
            metricsCollector.close();
            metricsCollector = null;
        }

        if (leaderElection != null) {
            LOGGER.debug("Stopping leader election");
            leaderElection.close();
            leaderElection = null;
        }

        if (eventListenerExecutor != null) {
            eventListenerExecutor.close();
            eventListenerExecutor = null;
            runsCompletedEventListeners.clear();
        }

        if (runHistoryCache != null) {
            runHistoryCache.invalidateAll();
            runHistoryCache = null;
        }

        setStatus(Status.STOPPED);
        LOGGER.debug("Stopped");
    }

    @Override
    public HealthCheckResponse probeHealth() {
        final var responseBuilder = HealthCheckResponse.named("dex-engine");
        boolean isUp = this.status == Status.RUNNING;

        responseBuilder.withData("internalStatus", this.status.name());

        if (externalEventBuffer != null) {
            isUp &= externalEventBuffer.status() == Buffer.Status.RUNNING;
            responseBuilder.withData("buffer:" + externalEventBuffer.name(), externalEventBuffer.status().name());
        }
        if (taskEventBuffer != null) {
            isUp &= taskEventBuffer.status() == Buffer.Status.RUNNING;
            responseBuilder.withData("buffer:" + taskEventBuffer.name(), taskEventBuffer.status().name());
        }

        for (final Map.Entry<String, TaskWorker> entry : taskWorkerByName.entrySet()) {
            isUp &= entry.getValue().status() == TaskWorker.Status.RUNNING;
            responseBuilder.withData("taskWorker:" + entry.getKey(), entry.getValue().status().name());
        }

        return responseBuilder.status(isUp).build();
    }

    @Override
    public <A, R> void registerWorkflow(
            Workflow<A, R> workflow,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.registerWorkflow(workflow, argumentConverter, resultConverter, lockTimeout);
    }

    <A, R> void registerWorkflowInternal(
            String workflowName,
            int workflowVersion,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            String defaultTaskQueueName,
            Duration lockTimeout,
            Workflow<A, R> workflow) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.registerWorkflow(
                workflowName,
                workflowVersion,
                argumentConverter,
                resultConverter,
                defaultTaskQueueName,
                lockTimeout,
                workflow);
    }

    @Override
    public <A, R> void registerActivity(
            Activity<A, R> activity,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            Duration lockTimeout) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.registerActivity(activity, argumentConverter, resultConverter, lockTimeout);
    }

    <A, R> void registerActivityInternal(
            String activityName,
            PayloadConverter<A> argumentConverter,
            PayloadConverter<R> resultConverter,
            String defaultTaskQueueName,
            Duration lockTimeout,
            Activity<A, R> activity) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        metadataRegistry.registerActivity(
                activityName,
                argumentConverter,
                resultConverter,
                defaultTaskQueueName,
                lockTimeout,
                activity);
    }

    @Override
    public void registerTaskWorker(TaskWorkerOptions options) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);

        if (options.type() == TaskType.ACTIVITY) {
            registerActivityTaskWorker(options);
        } else if (options.type() == TaskType.WORKFLOW) {
            registerWorkflowTaskWorker(options);
        } else {
            throw new IllegalArgumentException("Unknown task type: " + options.type());
        }
    }

    private void registerActivityTaskWorker(TaskWorkerOptions options) {
        final boolean queueExists = jdbi.withHandle(
                handle -> new ActivityDao(handle).doesActivityTaskQueueExists(options.queueName()));
        if (!queueExists) {
            throw new IllegalStateException("Activity task queue %s does not exist".formatted(options.queueName()));
        }

        final var worker = new ActivityTaskWorker(
                options.name(),
                this,
                options.minPollInterval(),
                options.pollBackoffFunction(),
                metadataRegistry,
                options.queueName(),
                options.maxConcurrency(),
                config.metrics().meterRegistry());

        if (taskWorkerByName.putIfAbsent("activity/" + options.name(), worker) != null) {
            throw new IllegalStateException(
                    "An task worker with name %s was already registered".formatted(options.name()));
        }
        if (activityWorkerByQueue.putIfAbsent(options.queueName(), worker) != null) {
            throw new IllegalStateException(
                    "An activity task worker for queue %s was already registered".formatted(options.queueName()));
        }
    }

    private void registerWorkflowTaskWorker(TaskWorkerOptions options) {
        final boolean queueExists = jdbi.withHandle(
                handle -> new WorkflowDao(handle).doesWorkflowTaskQueueExists(options.queueName()));
        if (!queueExists) {
            throw new IllegalStateException("Workflow task queue %s does not exist".formatted(options.queueName()));
        }

        final var worker = new WorkflowTaskWorker(
                options.name(),
                this,
                metadataRegistry,
                options.queueName(),
                options.minPollInterval(),
                options.pollBackoffFunction(),
                options.maxConcurrency(),
                config.metrics().meterRegistry());

        if (taskWorkerByName.putIfAbsent("workflow/" + options.name(), worker) != null) {
            throw new IllegalStateException(
                    "A task worker with name %s was already registered".formatted(options.name()));
        }
        if (workflowWorkerByQueue.putIfAbsent(options.queueName(), worker) != null) {
            throw new IllegalStateException(
                    "A workflow task worker for queue %s was already registered".formatted(options.queueName()));
        }
    }

    @Override
    public void addEventListener(DexEngineEventListener<?> listener) {
        requireStatusAnyOf(Status.CREATED, Status.STOPPED);
        requireNonNull(listener, "listener must not be null");
        switch (listener) {
            case WorkflowRunsCompletedEventListener it -> runsCompletedEventListeners.add(it);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<CreateWorkflowRunResponse> createRuns(Collection<? extends CreateWorkflowRunRequest<?>> requests) {
        final var now = Timestamps.now();
        final var nowInstant = toInstant(now);
        final var createWorkflowRunCommands = new ArrayList<CreateWorkflowRunCommand>(requests.size());
        final var messagesToCreate = new ArrayList<WorkflowMessage>(requests.size());

        for (final CreateWorkflowRunRequest<?> request : requests) {
            @SuppressWarnings("rawtypes") final WorkflowMetadata workflowMetadata =
                    metadataRegistry.getWorkflowMetadata(request.workflowName());

            final String taskQueueName = request.taskQueueName() != null
                    ? request.taskQueueName()
                    : workflowMetadata.defaultTaskQueueName();

            final UUID runId = timeBasedEpochRandomGenerator().generate();
            createWorkflowRunCommands.add(
                    new CreateWorkflowRunCommand(
                            request.requestId(),
                            runId,
                            /* parentId */ null,
                            request.workflowName(),
                            request.workflowVersion(),
                            request.workflowInstanceId(),
                            taskQueueName,
                            request.concurrencyKey(),
                            request.priority(),
                            request.labels(),
                            nowInstant));

            final var runCreatedBuilder = RunCreated.newBuilder()
                    .setWorkflowName(request.workflowName())
                    .setWorkflowVersion(request.workflowVersion())
                    .setTaskQueueName(taskQueueName)
                    .setPriority(request.priority());
            if (request.workflowInstanceId() != null) {
                runCreatedBuilder.setWorkflowInstanceId(request.workflowInstanceId());
            }
            if (request.concurrencyKey() != null) {
                runCreatedBuilder.setConcurrencyKey(request.concurrencyKey());
            }
            if (request.labels() != null) {
                runCreatedBuilder.putAllLabels(request.labels());
            }
            if (request.argument() != null) {
                final Payload argumentPayload;
                if (request.argument() instanceof final Payload payload) {
                    argumentPayload = payload;
                } else {
                    argumentPayload = workflowMetadata.argumentConverter().convertToPayload(request.argument());
                }
                runCreatedBuilder.setArgument(argumentPayload);
            }

            messagesToCreate.add(
                    new WorkflowMessage(
                            runId,
                            WorkflowEvent.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(now)
                                    .setRunCreated(runCreatedBuilder.build())
                                    .build()));
        }

        return jdbi.inTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final Map<UUID, UUID> createdRunIdByRequestId = dao.createRuns(createWorkflowRunCommands);
            if (createdRunIdByRequestId.isEmpty()) {
                return Collections.emptyList();
            }
            if (createdRunIdByRequestId.size() != createWorkflowRunCommands.size()) {
                messagesToCreate.removeIf(
                        command -> createdRunIdByRequestId.containsValue(command.recipientRunId()));
            }

            handle.afterCommit(() -> {
                for (final CreateWorkflowRunRequest<?> request : requests) {
                    if (createdRunIdByRequestId.containsKey(request.requestId())) {
                        continue;
                    }

                    final var tags = List.of(
                            Tag.of("workflowName", request.workflowName()),
                            Tag.of("workflowVersion", String.valueOf(request.workflowVersion())));

                    runsCreatedCounter.withTags(tags).increment();
                }

                if (workflowTaskScheduler != null) {
                    workflowTaskScheduler.nudge();
                }
            });

            final int createdMessages = dao.createMessages(messagesToCreate);
            assert createdMessages == messagesToCreate.size()
                    : "Created messages: actual=%d, expected=%d".formatted(
                    createdMessages, messagesToCreate.size());

            return createdRunIdByRequestId.entrySet().stream()
                    .map(entry -> new CreateWorkflowRunResponse(entry.getKey(), entry.getValue()))
                    .toList();
        });
    }


    @Override
    public @Nullable WorkflowRun getRunById(UUID id) {
        final List<WorkflowEvent> eventHistory = jdbi.withHandle(handle -> {
            final var dao = new WorkflowRunDao(handle);

            return PageIterator
                    .stream(pageToken -> dao.listRunHistory(
                            new ListWorkflowRunHistoryRequest(id)
                                    .withPageToken(pageToken)))
                    .map(WorkflowRunHistoryEntry::event)
                    .toList();
        });
        if (eventHistory.isEmpty()) {
            return null;
        }

        final var runState = new WorkflowRunState(id, eventHistory);

        return new WorkflowRun(
                runState.id(),
                runState.workflowName(),
                runState.workflowVersion(),
                runState.workflowInstanceId(),
                runState.status(),
                runState.customStatus(),
                runState.priority(),
                runState.concurrencyKey(),
                runState.labels(),
                runState.createdAt(),
                runState.updatedAt(),
                runState.startedAt(),
                runState.completedAt(),
                runState.argument(),
                runState.result(),
                runState.failure(),
                runState.eventHistory());
    }

    @Override
    public @Nullable WorkflowRunMetadata getRunMetadataById(UUID runId) {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRunMetadataById(runId));
    }

    @Override
    public @Nullable WorkflowRunMetadata getRunMetadataByInstanceId(String instanceId) {
        return jdbi.withHandle(handle -> new WorkflowDao(handle).getRunMetadataByInstanceId(instanceId));
    }

    @Override
    public Page<WorkflowRunMetadata> listRuns(ListWorkflowRunsRequest request) {
        return jdbi.withHandle(handle -> new WorkflowRunDao(handle).listRuns(request));
    }

    @Override
    public boolean existsRun(ExistsWorkflowRunRequest request) {
        return jdbi.withHandle(handle -> new WorkflowRunDao(handle).existsRun(request));
    }

    @Override
    public void requestRunCancellation(UUID runId, String reason) {
        final var cancellationEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunCanceled(RunCanceled.newBuilder()
                        .setReason(reason)
                        .build())
                .build();

        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunMetadata runMetadata = dao.getRunMetadataById(runId);
            if (runMetadata == null) {
                throw new NoSuchElementException("A workflow run with ID %s does not exist".formatted(runId));
            } else if (runMetadata.status().isTerminal()) {
                throw new IllegalStateException("Workflow run %s is already in terminal status".formatted(runId));
            }

            final boolean hasPendingCancellation = dao.getMessages(runId).stream().anyMatch(
                    event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.RUN_CANCELED);
            if (hasPendingCancellation) {
                throw new IllegalStateException("Cancellation of workflow run %s already pending".formatted(runId));
            }

            final int createdMessages = dao.createMessages(List.of(
                    new WorkflowMessage(runId, cancellationEvent)));
            assert createdMessages == 1;

            handle.afterCommit(() -> {
                if (workflowTaskScheduler != null) {
                    workflowTaskScheduler.nudge();
                }
            });
        });
    }

    @Override
    public void requestRunSuspension(UUID runId) {
        final var suspensionEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunSuspended(RunSuspended.getDefaultInstance())
                .build();

        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunMetadata runMetadata = dao.getRunMetadataById(runId);
            if (runMetadata == null) {
                throw new NoSuchElementException("A workflow run with ID %s does not exist".formatted(runId));
            } else if (runMetadata.status().isTerminal()) {
                throw new IllegalStateException("Workflow run %s is already in terminal status".formatted(runId));
            } else if (runMetadata.status() == WorkflowRunStatus.SUSPENDED) {
                throw new IllegalStateException("Workflow run %s is already suspended".formatted(runId));
            }

            final boolean hasPendingSuspension = dao.getMessages(runId).stream().anyMatch(
                    event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.RUN_SUSPENDED);
            if (hasPendingSuspension) {
                throw new IllegalStateException("Suspension of workflow run %s is already pending".formatted(runId));
            }

            final int createdMessages = dao.createMessages(List.of(
                    new WorkflowMessage(runId, suspensionEvent)));
            assert createdMessages == 1;

            handle.afterCommit(() -> {
                if (workflowTaskScheduler != null) {
                    workflowTaskScheduler.nudge();
                }
            });
        });
    }

    @Override
    public void requestRunResumption(UUID runId) {
        final var resumeEvent = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.now())
                .setRunResumed(RunResumed.getDefaultInstance())
                .build();

        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final WorkflowRunMetadata runMetadata = dao.getRunMetadataById(runId);
            if (runMetadata == null) {
                throw new NoSuchElementException("A workflow run with ID %s does not exist".formatted(runId));
            } else if (runMetadata.status().isTerminal()) {
                throw new IllegalStateException("Workflow run %s is already in terminal status".formatted(runId));
            } else if (runMetadata.status() != WorkflowRunStatus.SUSPENDED) {
                throw new IllegalStateException("Workflow run %s can not be resumed because it is not suspended".formatted(runId));
            }

            final boolean hasPendingResumption = dao.getMessages(runId).stream().anyMatch(
                    event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.RUN_RESUMED);
            if (hasPendingResumption) {
                throw new IllegalStateException("Resumption of workflow run %s is already pending".formatted(runId));
            }

            final int createdMessages = dao.createMessages(List.of(
                    new WorkflowMessage(runId, resumeEvent)));
            assert createdMessages == 1;

            handle.afterCommit(() -> {
                if (workflowTaskScheduler != null) {
                    workflowTaskScheduler.nudge();
                }
            });
        });
    }

    @Override
    public Page<WorkflowRunHistoryEntry> listRunHistory(ListWorkflowRunHistoryRequest request) {
        return jdbi.withHandle(handle -> new WorkflowRunDao(handle).listRunHistory(request));
    }

    @Override
    public CompletableFuture<Void> sendExternalEvent(ExternalEvent externalEvent) {
        requireStatusAnyOf(Status.RUNNING);

        try {
            return externalEventBuffer.add(externalEvent);
        } catch (InterruptedException | TimeoutException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean createTaskQueue(CreateTaskQueueRequest request) {
        return jdbi.inTransaction(handle -> switch (request.type()) {
            case ACTIVITY -> new ActivityDao(handle).createActivityTaskQueue(request);
            case WORKFLOW -> new WorkflowDao(handle).createWorkflowTaskQueue(request);
        });
    }

    @Override
    public boolean updateTaskQueue(UpdateTaskQueueRequest request) {
        return jdbi.inTransaction(handle -> switch (request.type()) {
            case ACTIVITY -> new ActivityDao(handle).updateActivityTaskQueue(request);
            case WORKFLOW -> new WorkflowDao(handle).updateWorkflowTaskQueue(request);
        });
    }

    @Override
    public Page<TaskQueue> listTaskQueues(ListTaskQueuesRequest request) {
        return jdbi.withHandle(handle -> switch (request.type()) {
            case ACTIVITY -> new ActivityDao(handle).listActivityTaskQueues(request);
            case WORKFLOW -> new WorkflowDao(handle).listWorkflowTaskQueues(request);
        });
    }

    void onTaskEvent(TaskEvent taskEvent) {
        final CompletableFuture<Void> future;
        try {
            future = taskEventBuffer.add(taskEvent);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "Interrupted while waiting for buffer to accept task event", e);
        } catch (TimeoutException e) {
            // TODO: Retry
            throw new IllegalStateException(
                    "Timed out while waiting for buffer to accept task event", e);
        }

        try {
            // TODO: Find appropriate timeout.
            future.get(15, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "Interrupted while waiting for task event to be processed", e);
        } catch (TimeoutException e) {
            throw new IllegalStateException(
                    "Timed out while waiting for task event to be processed", e);
        } catch (ExecutionException e) {
            throw new IllegalStateException(e.getCause());
        }
    }

    private void flushExternalEvents(List<ExternalEvent> externalEvents) {
        jdbi.useTransaction(handle -> {
            final var dao = new WorkflowDao(handle);
            final var now = Timestamps.now();

            final var messagesToCreate = new ArrayList<WorkflowMessage>(externalEvents.size());
            for (final ExternalEvent externalEvent : externalEvents) {
                final var subjectBuilder = ExternalEventReceived.newBuilder()
                        .setId(externalEvent.eventId());
                if (externalEvent.payload() != null) {
                    subjectBuilder.setPayload(externalEvent.payload());
                }

                messagesToCreate.add(
                        new WorkflowMessage(
                                externalEvent.workflowRunId(),
                                WorkflowEvent.newBuilder()
                                        .setId(-1)
                                        .setTimestamp(now)
                                        .setExternalEventReceived(subjectBuilder)
                                        .build()));
            }

            dao.createMessages(messagesToCreate);

            handle.afterCommit(() -> {
                if (workflowTaskScheduler != null) {
                    workflowTaskScheduler.nudge();
                }
            });
        });
    }

    List<WorkflowTask> pollWorkflowTasks(
            String queueName,
            Collection<PollWorkflowTaskCommand> commands,
            int limit) {
        return jdbi.inTransaction(handle -> {
            final var dao = new WorkflowDao(handle);

            final Map<UUID, PolledWorkflowTask> polledTaskByRunId =
                    dao.pollAndLockWorkflowTasks(this.config.instanceId(), queueName, commands, limit);
            if (polledTaskByRunId.isEmpty()) {
                return Collections.emptyList();
            }

            final var historyRequests = new ArrayList<GetWorkflowRunHistoryRequest>(polledTaskByRunId.size());
            final var cachedHistoryByRunId = new HashMap<UUID, List<WorkflowEvent>>(polledTaskByRunId.size());

            // Try to populate event histories from cache first.
            for (final var entry : polledTaskByRunId.entrySet()) {
                final UUID runId = entry.getKey();
                final PolledWorkflowTask polledTask = entry.getValue();
                final CachedWorkflowRunHistory cachedHistory = runHistoryCache.getIfPresent(
                        new WorkflowRunHistoryCacheKey(runId, polledTask.continuedAsNewGeneration()));
                if (cachedHistory == null) {
                    historyRequests.add(new GetWorkflowRunHistoryRequest(runId, -1));
                } else {
                    cachedHistoryByRunId.put(runId, cachedHistory.events());
                    historyRequests.add(new GetWorkflowRunHistoryRequest(runId, cachedHistory.maxSequenceNumber()));
                }
            }

            final Map<UUID, PolledWorkflowEvents> polledEventsByRunId = dao.pollRunEvents(historyRequests);

            return polledTaskByRunId.values().stream()
                    .map(polledTask -> {
                        final PolledWorkflowEvents polledEvents = polledEventsByRunId.get(polledTask.runId());
                        final List<WorkflowEvent> cachedHistoryEvents = cachedHistoryByRunId.get(polledTask.runId());

                        var historySize = polledEvents.history().size();
                        if (cachedHistoryEvents != null) {
                            historySize += cachedHistoryEvents.size();
                        }

                        final var history = new ArrayList<WorkflowEvent>(historySize);
                        if (cachedHistoryEvents != null) {
                            history.addAll(cachedHistoryEvents);
                        }
                        history.addAll(polledEvents.history());

                        runHistoryCache.put(
                                new WorkflowRunHistoryCacheKey(
                                        polledTask.runId(),
                                        polledTask.continuedAsNewGeneration()),
                                new CachedWorkflowRunHistory(
                                        history,
                                        polledEvents.maxHistorySequenceNumber()));

                        return WorkflowTask.of(
                                polledTask,
                                history,
                                polledEvents.inbox(),
                                polledEvents.inboxMessageIds());
                    })
                    .toList();
        });
    }

    private void abandonWorkflowTasksInternal(
            WorkflowDao dao,
            Collection<WorkflowTaskAbandonedEvent> events) {
        final int abandonedTasks = dao.abandonWorkflowTasks(
                this.config.instanceId(),
                events.stream()
                        .map(WorkflowTaskAbandonedEvent::task)
                        .toList());
        assert abandonedTasks == events.size()
                : "Abandoned tasks: actual=%d, expected=%d".formatted(abandonedTasks, events.size());
    }

    private void completeWorkflowTasksInternal(
            WorkflowDao workflowDao,
            ActivityDao activityDao,
            Collection<WorkflowTaskCompletedEvent> events) {
        final List<WorkflowRunState> actionableRuns = events.stream()
                .map(WorkflowTaskCompletedEvent::workflowRunState)
                .collect(Collectors.toList());

        final List<UUID> updatedRunIds = workflowDao.updateAndUnlockRuns(
                this.config.instanceId(),
                events.stream()
                        .map(event -> new UpdateAndUnlockRunCommand(
                                event.workflowRunState().id(),
                                event.workflowRunState().taskQueueName(),
                                event.workflowRunState().status(),
                                event.workflowRunState().customStatus(),
                                event.workflowRunState().continuedAsNew(),
                                event.workflowRunState().createdAt(),
                                event.workflowRunState().updatedAt(),
                                event.workflowRunState().startedAt(),
                                event.workflowRunState().completedAt(),
                                event.task().lock().version()))
                        .toList());

        if (updatedRunIds.size() != events.size()) {
            final Set<UUID> notUpdatedRunIds = events.stream()
                    .map(WorkflowTaskCompletedEvent::workflowRunState)
                    .map(WorkflowRunState::id)
                    .filter(runId -> !updatedRunIds.contains(runId))
                    .collect(Collectors.toSet());
            for (final UUID runId : notUpdatedRunIds) {
                LOGGER.warn("""
                        Workflow run {} was not updated, indicating modification \
                        by another worker instance""", runId);
            }

            // Since we lost the lock on these runs, we can't act upon them anymore.
            // Note that this is expected behavior and not necessarily reason for concern.
            actionableRuns.removeIf(run -> notUpdatedRunIds.contains(run.id()));
        }

        final var createHistoryEntryCommands = new ArrayList<CreateWorkflowRunHistoryEntryCommand>(events.size() * 2);
        final var messagesToCreate = new ArrayList<WorkflowMessage>(events.size() * 2);
        final var createWorkflowRunCommands = new ArrayList<CreateWorkflowRunCommand>();
        final var continuedAsNewRunIds = new ArrayList<UUID>();
        final var runHistoryCacheKeysToInvalidate = new ArrayList<WorkflowRunHistoryCacheKey>();
        final Map<UUID, Integer> continuedAsNewGenerationByRunId = events.stream()
                .collect(Collectors.toMap(
                        event -> event.workflowRunState().id(),
                        event -> event.task().continuedAsNewGeneration(),
                        (a, b) -> a));
        final var createActivityTaskCommands = new ArrayList<CreateActivityTaskCommand>();
        final var activityTasksToDelete = new ArrayList<ActivityTaskId>();
        final var completedRuns = new ArrayList<WorkflowRunMetadata>();

        final var now = Timestamps.now();
        final var nowInstant = toInstant(now);

        for (final WorkflowRunState run : actionableRuns) {
            if (!runsCompletedEventListeners.isEmpty() && run.status().isTerminal()) {
                completedRuns.add(new WorkflowRunMetadata(
                        run.id(),
                        run.workflowName(),
                        run.workflowVersion(),
                        run.workflowInstanceId(),
                        run.taskQueueName(),
                        run.status(),
                        run.customStatus(),
                        run.priority(),
                        run.concurrencyKey(),
                        run.labels(),
                        run.createdAt(),
                        run.updatedAt(),
                        run.startedAt(),
                        run.completedAt()));
            }

            // Write all processed events to history.
            int sequenceNumber = run.eventHistory().size();
            for (final WorkflowEvent newEvent : run.newEvents()) {
                createHistoryEntryCommands.add(
                        new CreateWorkflowRunHistoryEntryCommand(
                                run.id(),
                                sequenceNumber++,
                                newEvent));
            }

            for (final WorkflowMessage message : run.pendingMessages()) {
                // If the outbound message is a RunCreated event, the recipient
                // workflow run will need to be created first.
                boolean shouldCreateWorkflowRun = message.event().hasRunCreated();

                // If this is the run re-scheduling itself as part of he "continue as new"
                // mechanism, no new run needs to be created.
                shouldCreateWorkflowRun &= !(run.continuedAsNew() && message.recipientRunId().equals(run.id()));

                if (shouldCreateWorkflowRun) {
                    createWorkflowRunCommands.add(
                            new CreateWorkflowRunCommand(
                                    UUID.randomUUID(),
                                    message.recipientRunId(),
                                    /* parentId */ run.id(),
                                    message.event().getRunCreated().getWorkflowName(),
                                    message.event().getRunCreated().getWorkflowVersion(),
                                    message.event().getRunCreated().hasWorkflowInstanceId()
                                            ? message.event().getRunCreated().getWorkflowInstanceId()
                                            : null,
                                    message.event().getRunCreated().getTaskQueueName(),
                                    message.event().getRunCreated().hasConcurrencyKey()
                                            ? message.event().getRunCreated().getConcurrencyKey()
                                            : null,
                                    message.event().getRunCreated().getPriority(),
                                    message.event().getRunCreated().getLabelsCount() > 0
                                            ? message.event().getRunCreated().getLabelsMap()
                                            : null,
                                    nowInstant));
                }

                messagesToCreate.add(message);
            }

            for (final WorkflowEvent newEvent : run.pendingActivityTaskCreatedEvents()) {
                createActivityTaskCommands.add(
                        new CreateActivityTaskCommand(
                                run.id(),
                                newEvent.getId(),
                                newEvent.getActivityTaskCreated().getName(),
                                newEvent.getActivityTaskCreated().getQueueName(),
                                newEvent.getActivityTaskCreated().getPriority(),
                                newEvent.getActivityTaskCreated().hasArgument()
                                        ? newEvent.getActivityTaskCreated().getArgument()
                                        : null,
                                newEvent.getActivityTaskCreated().getRetryPolicy()));
            }

            // If the run reached a terminal state, clean up any pending
            // work such as child runs and activity tasks.
            if (run.status().isTerminal()) {
                for (final UUID childRunId : run.pendingChildRunIds()) {
                    messagesToCreate.add(
                            new WorkflowMessage(
                                    childRunId,
                                    WorkflowEvent.newBuilder()
                                            .setId(-1)
                                            .setTimestamp(now)
                                            .setRunCanceled(RunCanceled.newBuilder()
                                                    .setReason("Parent terminated with status " + run.status())
                                                    .build())
                                            .build()));
                }

                // Pending activities should be rare, but this can happen when a
                // workflow fails or is canceled before it had the chance to await activity results.
                // What we want to avoid is activity tasks occupying queue capacity
                // when their outcome is no longer of any use anyway.
                if (!run.pendingActivityTaskIds().isEmpty()) {
                    LOGGER.warn("""
                            Run {} of workflow {} terminated while {} activities \
                            were still pending. Pending activity tasks will be deleted.\
                            """, run.id(), run.workflowName(), run.pendingActivityTaskIds().size());
                    activityTasksToDelete.addAll(run.pendingActivityTaskIds());
                }
            }

            if (run.continuedAsNew()) {
                continuedAsNewRunIds.add(run.id());
                runHistoryCacheKeysToInvalidate.add(
                        new WorkflowRunHistoryCacheKey(
                                run.id(),
                                continuedAsNewGenerationByRunId.get(run.id())));
            }
        }

        if (!continuedAsNewRunIds.isEmpty()) {
            workflowDao.truncateRunHistories(continuedAsNewRunIds);
            workflowDao.getJdbiHandle().afterCommit(
                    () -> runHistoryCache.invalidateAll(runHistoryCacheKeysToInvalidate));
        }

        if (!createHistoryEntryCommands.isEmpty()) {
            final int historyEntriesCreated = workflowDao.createRunHistoryEntries(createHistoryEntryCommands);
            assert historyEntriesCreated == createHistoryEntryCommands.size()
                    : "Created history entries: actual=%d, expected=%d".formatted(
                    historyEntriesCreated, createHistoryEntryCommands.size());
        }

        if (!createWorkflowRunCommands.isEmpty()) {
            final Map<UUID, UUID> createdRunIdByRequestId = workflowDao.createRuns(createWorkflowRunCommands);
            workflowDao.getJdbiHandle().afterCommit(() -> {
                for (final CreateWorkflowRunCommand cmd : createWorkflowRunCommands) {
                    if (!createdRunIdByRequestId.containsKey(cmd.requestId())) {
                        continue;
                    }

                    final var tags = List.of(
                            Tag.of("workflowName", cmd.workflowName()),
                            Tag.of("workflowVersion", String.valueOf(cmd.workflowVersion())));

                    runsCreatedCounter.withTags(tags).increment();
                }
            });

            // When another workflow run with identical instance ID already exists in non-terminal
            // state, a new run will not be created. Since runs are created due to a parent workflow
            // spawning a child workflow, we need to inform the parent about this failure.
            //
            // This scenario should be pretty rare but needs to be dealt with nonetheless.
            if (createdRunIdByRequestId.size() != createWorkflowRunCommands.size()) {
                final ListIterator<WorkflowMessage> messageIterator = messagesToCreate.listIterator();
                while (messageIterator.hasNext()) {
                    final WorkflowMessage pendingMessage = messageIterator.next();

                    if (!pendingMessage.event().hasRunCreated()
                            || !pendingMessage.event().getRunCreated().hasParentRun()) {
                        // Only inspect RunCreated events with a parent.
                        continue;
                    }

                    if (createdRunIdByRequestId.containsValue(pendingMessage.recipientRunId())) {
                        // The message is addressed to a run that was successfully created; Nothing to do.
                        continue;
                    }

                    final RunCreated runCreated = pendingMessage.event().getRunCreated();
                    final RunCreated.ParentRun parentRun = runCreated.getParentRun();
                    final var exception = new InternalFailureException(
                            "Another run already exists in non-terminal state for instance ID: " + runCreated.getWorkflowInstanceId());

                    final var childRunFailedEvent = WorkflowEvent.newBuilder()
                            .setId(-1)
                            .setTimestamp(now)
                            .setChildRunFailed(
                                    ChildRunFailed.newBuilder()
                                            .setChildRunCreatedEventId(parentRun.getChildRunCreatedEventId())
                                            .setFailure(FailureConverter.toFailure(exception))
                                            .build())
                            .build();

                    messageIterator.set(new WorkflowMessage(UUID.fromString(parentRun.getId()), childRunFailedEvent));
                }
            }
        }

        if (!messagesToCreate.isEmpty()) {
            final int createdMessages = workflowDao.createMessages(messagesToCreate);
            assert createdMessages == messagesToCreate.size()
                    : "Created messages: actual=%d, expected=%d".formatted(
                    createdMessages, messagesToCreate.size());
        }

        if (!createActivityTaskCommands.isEmpty()) {
            final int createdActivityTasks = activityDao.createActivityTasks(createActivityTaskCommands);
            assert createdActivityTasks == createActivityTaskCommands.size()
                    : "Created activity tasks: actual=%d, expected=%d".formatted(
                    createdActivityTasks, createActivityTaskCommands.size());
        }

        if (!activityTasksToDelete.isEmpty()) {
            // This is fire-and-forget, since activity tasks have possibly been
            // completed while we were processing workflow task completions.
            activityDao.deleteActivityTasks(activityTasksToDelete);
        }

        // Delete *all* messages for terminated runs,
        // or only actually processed messages for non-terminated runs.
        // The latter is crucial since new messages could have
        // been added in the meantime.
        final int deletedMessages = workflowDao.deleteMessages(
                events.stream()
                        .filter(event -> updatedRunIds.contains(event.workflowRunState().id()))
                        .map(event -> new DeleteWorkflowMessagesCommand(
                                event.workflowRunState().id(),
                                !event.workflowRunState().status().isTerminal()
                                        ? event.task().inboxMessageIds()
                                        : null))
                        .toList());
        assert deletedMessages >= updatedRunIds.size()
                : "Deleted messages: actual=%d, expectedAtLeast=%d".formatted(
                deletedMessages, updatedRunIds.size());

        if (!completedRuns.isEmpty()) {
            workflowDao.getJdbiHandle().afterCommit(
                    () -> maybeNotifyEventListeners(
                            List.of(new WorkflowRunsCompletedEvent(completedRuns))));
        }
    }

    List<ActivityTask> pollActivityTasks(
            String queueName,
            Collection<PollActivityTaskCommand> commands,
            int limit) {
        return jdbi.inTransaction(handle -> {
            final var activityDao = new ActivityDao(handle);

            return activityDao.pollAndLockActivityTasks(
                            this.config.instanceId(),
                            queueName,
                            commands,
                            limit).stream()
                    .map(ActivityTask::of)
                    .toList();
        });
    }

    private void abandonActivityTasksInternal(
            ActivityDao activityDao,
            Collection<ActivityTaskAbandonedEvent> events) {
        final int abandonedTasks = activityDao.abandonActivityTasks(
                events.stream()
                        .map(ActivityTaskAbandonedEvent::task)
                        .toList());
        assert abandonedTasks == events.size()
                : "Abandoned tasks: actual=%d, expected=%d".formatted(abandonedTasks, events.size());
    }

    private void completeActivityTasksInternal(
            WorkflowDao workflowDao,
            ActivityDao activityDao,
            Collection<ActivityTaskCompletedEvent> events) {
        final var tasksToDelete = new ArrayList<ActivityTask>(events.size());
        final var workflowMessageByTaskId = new LinkedHashMap<ActivityTaskId, WorkflowMessage>(events.size());

        for (final ActivityTaskCompletedEvent event : events) {
            tasksToDelete.add(event.task());

            final var taskCompletedBuilder = ActivityTaskCompleted.newBuilder()
                    .setActivityTaskCreatedEventId(event.task().id().createdEventId());
            if (event.result() != null) {
                taskCompletedBuilder.setResult(event.result());
            }
            workflowMessageByTaskId.put(
                    event.task().id(),
                    new WorkflowMessage(
                            event.task().id().workflowRunId(),
                            WorkflowEvent.newBuilder()
                                    .setId(-1)
                                    .setTimestamp(toProtoTimestamp(event.timestamp()))
                                    .setActivityTaskCompleted(taskCompletedBuilder.build())
                                    .build()));
        }

        final List<ActivityTaskId> deletedTaskIds = activityDao.deleteLockedActivityTasks(tasksToDelete);
        if (deletedTaskIds.size() != tasksToDelete.size()) {
            workflowMessageByTaskId.keySet().removeIf(taskId -> {
                if (!deletedTaskIds.contains(taskId)) {
                    LOGGER.warn("""
                            A successfully completed activity task with ID {} could not be deleted, \
                            likely because its lock expired, causing another worker to pick it up. \
                            Expect duplicate task executions. To prevent this from happening, \
                            consider increasing the activity's lock timeout, and sending heartbeats \
                            more frequently.""", taskId);
                    return true;
                }

                return false;
            });
        }

        if (!workflowMessageByTaskId.isEmpty()) {
            final int createdMessages = workflowDao.createMessages(workflowMessageByTaskId.sequencedValues());
            assert createdMessages == workflowMessageByTaskId.size()
                    : "Created workflow messages: actual=%d, expected=%d".formatted(
                    createdMessages, workflowMessageByTaskId.size());
        }
    }

    private void failActivityTasksInternal(
            WorkflowDao workflowDao,
            ActivityDao activityDao,
            Collection<ActivityTaskFailedEvent> events) {
        final var tasksToDelete = new ArrayList<ActivityTask>(events.size());
        final var workflowMessageByTaskId = new LinkedHashMap<ActivityTaskId, WorkflowMessage>(events.size());
        final var retriesToSchedule = new ArrayList<ScheduleActivityTaskRetryCommand>();

        for (final ActivityTaskFailedEvent event : events) {
            final ActivityTask task = event.task();
            if (event.retryAt() == null) {
                tasksToDelete.add(task);

                workflowMessageByTaskId.put(
                        task.id(),
                        new WorkflowMessage(
                                task.id().workflowRunId(),
                                WorkflowEvent.newBuilder()
                                        .setId(-1)
                                        .setTimestamp(toProtoTimestamp(event.timestamp()))
                                        .setActivityTaskFailed(ActivityTaskFailed.newBuilder()
                                                .setActivityTaskCreatedEventId(task.id().createdEventId())
                                                .setAttempts(task.attempt())
                                                .setFailure(FailureConverter.toFailure(event.exception()))
                                                .build())
                                        .build()));
            } else {
                retriesToSchedule.add(new ScheduleActivityTaskRetryCommand(task, event.retryAt()));
            }
        }

        if (!tasksToDelete.isEmpty()) {
            final List<ActivityTaskId> deletedTaskIds = activityDao.deleteLockedActivityTasks(tasksToDelete);
            if (deletedTaskIds.size() != tasksToDelete.size()) {
                workflowMessageByTaskId.keySet().removeIf(taskId -> {
                    if (!deletedTaskIds.contains(taskId)) {
                        LOGGER.warn("""
                                A terminally failed activity task with ID {} could not be deleted, \
                                likely because its lock expired, causing another worker to pick it up. \
                                Expect duplicate task executions. To prevent this from happening, \
                                consider increasing the activity's lock timeout, and sending heartbeats \
                                more frequently.""", taskId);
                        return true;
                    }

                    return false;
                });
            }
        }

        if (!workflowMessageByTaskId.isEmpty()) {
            final int createdWorkflowMessages = workflowDao.createMessages(workflowMessageByTaskId.sequencedValues());
            assert createdWorkflowMessages == workflowMessageByTaskId.size()
                    : "Created workflow messages: actual=%d, expected=%d".formatted(
                    createdWorkflowMessages, workflowMessageByTaskId.size());
        }

        if (!retriesToSchedule.isEmpty()) {
            final int tasksScheduledForRetry =
                    activityDao.scheduleActivityTasksForRetry(
                            this.config.instanceId(), retriesToSchedule);
            assert tasksScheduledForRetry == retriesToSchedule.size()
                    : "Scheduled activity tasks: actual=%d, expected=%d".formatted(
                    tasksScheduledForRetry, retriesToSchedule.size());
        }
    }

    CompletableFuture<TaskLock> heartbeatActivityTask(
            ActivityTaskId taskId,
            TaskLock taskLock,
            Duration lockTimeout) {
        final var future = new CompletableFuture<TaskLock>();
        final var heartbeat = new ActivityTaskHeartbeat(taskId, taskLock, lockTimeout, future);

        try {
            activityTaskHeartbeatBuffer.add(heartbeat);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            future.completeExceptionally(e);
        } catch (TimeoutException e) {
            future.completeExceptionally(e);
        }

        return future;
    }

    private void processActivityTaskHeartbeats(List<ActivityTaskHeartbeat> heartbeats) {
        // TODO: Complete all futures exceptionally when transaction fails.
        final Map<ActivityTaskId, TaskLock> lockByTaskId = jdbi.inTransaction(handle -> {
            final Update update = handle.createUpdate("""
                    update dex_activity_task as task
                       set locked_until = locked_until + t.lock_timeout
                         , lock_version = task.lock_version + 1
                         , updated_at = now()
                      from unnest(:queueNames, :workflowRunIds, :createdEventIds, :lockTimeouts, :lockVersions)
                        as t(queue_name, workflow_run_id, created_event_id, lock_timeout, lock_version)
                     where task.queue_name = t.queue_name
                       and task.workflow_run_id = t.workflow_run_id
                       and task.created_event_id = t.created_event_id
                       and task.locked_by = :engineInstanceId
                       and task.lock_version = t.lock_version
                    returning task.queue_name
                            , task.workflow_run_id
                            , task.created_event_id
                            , task.locked_until
                            , task.lock_version
                    """);

            final var queueNames = new String[heartbeats.size()];
            final var workflowRunIds = new UUID[heartbeats.size()];
            final var createdEventIds = new int[heartbeats.size()];
            final var lockTimeouts = new Duration[heartbeats.size()];
            final var lockVersions = new int[heartbeats.size()];

            int i = 0;
            for (final ActivityTaskHeartbeat heartbeat : heartbeats) {
                queueNames[i] = heartbeat.taskId().queueName();
                workflowRunIds[i] = heartbeat.taskId().workflowRunId();
                createdEventIds[i] = heartbeat.taskId().createdEventId();
                lockTimeouts[i] = heartbeat.lockTimeout();
                lockVersions[i] = heartbeat.lock().version();
                i++;
            }

            return update
                    .bind("engineInstanceId", config.instanceId())
                    .bind("queueNames", queueNames)
                    .bind("workflowRunIds", workflowRunIds)
                    .bind("createdEventIds", createdEventIds)
                    .bind("lockTimeouts", lockTimeouts)
                    .bind("lockVersions", lockVersions)
                    .executeAndReturnGeneratedKeys("locked_until")
                    .map((rs, ctx) -> Map.entry(
                            new ActivityTaskId(
                                    rs.getString("queue_name"),
                                    rs.getObject("workflow_run_id", UUID.class),
                                    rs.getInt("created_event_id")),
                            new TaskLock(
                                    ctx.findColumnMapperFor(Instant.class).orElseThrow().map(rs, "locked_until", ctx),
                                    rs.getInt("lock_version"))))
                    .collectToMap(Map.Entry::getKey, Map.Entry::getValue);
        });

        final Map<ActivityTaskId, CompletableFuture<TaskLock>> futureByTaskId = heartbeats.stream()
                .collect(Collectors.toMap(
                        ActivityTaskHeartbeat::taskId,
                        ActivityTaskHeartbeat::future));

        for (final var entry : futureByTaskId.entrySet()) {
            final ActivityTaskId taskId = entry.getKey();
            final CompletableFuture<TaskLock> future = entry.getValue();

            final TaskLock lock = lockByTaskId.get(taskId);
            if (lock != null) {
                future.complete(lock);
            } else {
                future.completeExceptionally(new IllegalStateException());
            }
        }
    }

    private void flushTaskEvents(List<TaskEvent> taskEvents) {
        final var activityTaskAbandonedEvents = new ArrayList<ActivityTaskAbandonedEvent>();
        final var completeActivityTaskCommands = new ArrayList<ActivityTaskCompletedEvent>();
        final var failActivityTaskCommands = new ArrayList<ActivityTaskFailedEvent>();
        final var abandonWorkflowTaskCommands = new ArrayList<WorkflowTaskAbandonedEvent>();
        final var completeWorkflowTaskCommands = new ArrayList<WorkflowTaskCompletedEvent>();

        for (final TaskEvent command : taskEvents) {
            switch (command) {
                case ActivityTaskAbandonedEvent it -> activityTaskAbandonedEvents.add(it);
                case ActivityTaskCompletedEvent it -> completeActivityTaskCommands.add(it);
                case ActivityTaskFailedEvent it -> failActivityTaskCommands.add(it);
                case WorkflowTaskAbandonedEvent it -> abandonWorkflowTaskCommands.add(it);
                case WorkflowTaskCompletedEvent it -> completeWorkflowTaskCommands.add(it);
            }
        }

        final boolean hasWorkflowTaskCompletions = !completeWorkflowTaskCommands.isEmpty();
        final boolean hasActivityTaskCompletionsOrFailures =
                !completeActivityTaskCommands.isEmpty()
                        || !failActivityTaskCommands.isEmpty();

        jdbi.useTransaction(handle -> {
            final var workflowDao = new WorkflowDao(handle);
            final var activityDao = new ActivityDao(handle);

            if (!activityTaskAbandonedEvents.isEmpty()) {
                abandonActivityTasksInternal(activityDao, activityTaskAbandonedEvents);
            }
            if (!completeActivityTaskCommands.isEmpty()) {
                completeActivityTasksInternal(workflowDao, activityDao, completeActivityTaskCommands);
            }
            if (!failActivityTaskCommands.isEmpty()) {
                failActivityTasksInternal(workflowDao, activityDao, failActivityTaskCommands);
            }
            if (!abandonWorkflowTaskCommands.isEmpty()) {
                abandonWorkflowTasksInternal(workflowDao, abandonWorkflowTaskCommands);
            }
            if (!completeWorkflowTaskCommands.isEmpty()) {
                completeWorkflowTasksInternal(workflowDao, activityDao, completeWorkflowTaskCommands);
            }

            handle.afterCommit(() -> {
                if (hasWorkflowTaskCompletions) {
                    if (activityTaskScheduler != null) {
                        activityTaskScheduler.nudge();
                    }
                }
                if (hasWorkflowTaskCompletions || hasActivityTaskCompletionsOrFailures) {
                    if (workflowTaskScheduler != null) {
                        workflowTaskScheduler.nudge();
                    }
                }
            });
        });
    }

    private void maybeNotifyEventListeners(final Collection<DexEngineEvent> events) {
        if (eventListenerExecutor == null || events.isEmpty()) {
            return;
        }

        for (final DexEngineEvent event : events) {
            switch (event) {
                case WorkflowRunsCompletedEvent it -> {
                    for (final WorkflowRunsCompletedEventListener listener : runsCompletedEventListeners) {
                        eventListenerExecutor.execute(() -> {
                            try {
                                listener.onEvent(it);
                            } catch (RuntimeException e) {
                                LOGGER.warn("Failed to notify event listener {}", listener.getClass().getName(), e);
                            }
                        });
                    }
                }
            }
        }
    }

    MetadataRegistry executorMetadataRegistry() {
        return metadataRegistry;
    }

    private void invalidateCompletedRunsHistoryCache(WorkflowRunsCompletedEvent event) {
        if (runHistoryCache == null) {
            return;
        }

        final Set<UUID> completedRunIds = event.completedRuns().stream()
                .map(WorkflowRunMetadata::id)
                .collect(Collectors.toSet());
        runHistoryCache.asMap().keySet().removeIf(
                key -> completedRunIds.contains(key.runId()));
    }

    private void recordCompletedRunsMetrics(WorkflowRunsCompletedEvent event) {
        for (final WorkflowRunMetadata completedRun : event.completedRuns()) {
            final var tags = List.of(
                    Tag.of("workflowName", completedRun.workflowName()),
                    Tag.of("workflowVersion", String.valueOf(completedRun.workflowVersion())),
                    Tag.of("status", completedRun.status().toString()));

            runsCompletedCounter.withTags(tags).increment();
        }
    }

    private void setStatus(Status newStatus) {
        statusLock.lock();
        try {
            if (this.status == newStatus) {
                return;
            }

            if (this.status.canTransitionTo(newStatus)) {
                LOGGER.info("Transitioning from status {} to {}", this.status, newStatus);
                this.status = newStatus;
                return;
            }

            throw new IllegalStateException(
                    "Can not transition from status %s to %s".formatted(this.status, newStatus));
        } finally {
            statusLock.unlock();
        }
    }

    private void requireStatusAnyOf(Status... expectedStatuses) {
        for (final Status expectedStatus : expectedStatuses) {
            if (this.status == expectedStatus) {
                return;
            }
        }

        throw new IllegalStateException(
                "Engine must be in state any of %s, but is %s".formatted(expectedStatuses, this.status));
    }

}
