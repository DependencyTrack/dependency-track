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

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.Awaitable;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.dex.api.failure.ChildWorkflowFailureException;
import org.dependencytrack.dex.api.failure.FailureException;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.api.payload.PayloadConverter;
import org.dependencytrack.dex.engine.api.DexEngineConfig;
import org.dependencytrack.dex.engine.api.ExternalEvent;
import org.dependencytrack.dex.engine.api.TaskQueue;
import org.dependencytrack.dex.engine.api.TaskQueueStatus;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunHistoryEntry;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEventListener;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ExistsWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.engine.api.request.UpdateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.response.CreateWorkflowRunResponse;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.dex.proto.payload.v1.Payload;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.payload.PayloadConverters.stringConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_CANCELLED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;

@Testcontainers
class DexEngineImplTest {

    @Container
    private static final PostgresTestContainer postgresContainer = new PostgresTestContainer();
    private static final String WORKFLOW_TASK_QUEUE = "default";
    private static final String ACTIVITY_TASK_QUEUE = "default";

    private HikariDataSource dataSource;
    private DexEngineImpl engine;

    @BeforeEach
    void beforeEach() {
        postgresContainer.truncateTables();

        final var hikariConfig = new HikariConfig();
        hikariConfig.setJdbcUrl(postgresContainer.getJdbcUrl());
        hikariConfig.setUsername(postgresContainer.getUsername());
        hikariConfig.setPassword(postgresContainer.getPassword());
        hikariConfig.setMaximumPoolSize(5);
        hikariConfig.setConnectionTimeout(1000);

        dataSource = new HikariDataSource(hikariConfig);

        final var config = new DexEngineConfig(dataSource);
        config.activityTaskScheduler().setPollInterval(Duration.ofMillis(10));
        config.activityTaskScheduler().setPollBackoffFunction(IntervalFunction.of(10));
        config.workflowTaskScheduler().setPollInterval(Duration.ofMillis(10));
        config.workflowTaskScheduler().setPollBackoffFunction(IntervalFunction.of(10));
        config.taskEventBuffer().setFlushInterval(Duration.ofMillis(10));

        engine = new DexEngineImpl(config);
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, WORKFLOW_TASK_QUEUE, 10));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, ACTIVITY_TASK_QUEUE, 10));
    }

    @AfterEach
    void afterEach() {
        if (engine != null) {
            try {
                engine.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        if (dataSource != null) {
            dataSource.close();
        }
    }

    @Test
    void shouldRunWorkflowWithArgumentAndResult() {
        registerWorkflow("test", stringConverter(), stringConverter(), (ctx, _) -> {
            ctx.setStatus("someCustomStatus");
            return "someResult";
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>("test", 1)
                        .withConcurrencyKey("someConcurrencyKey")
                        .withPriority(6)
                        .withLabels(Map.of("label-a", "123", "label-b", "321"))
                        .withArgument("someArgument"));

        final WorkflowRunMetadata completedRun = awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(completedRun.customStatus()).isEqualTo("someCustomStatus");
        assertThat(completedRun.concurrencyKey()).isEqualTo("someConcurrencyKey");
        assertThat(completedRun.priority()).isEqualTo(6);
        assertThat(completedRun.labels()).containsOnlyKeys("label-a", "label-b");
        assertThat(completedRun.createdAt()).isNotNull();
        assertThat(completedRun.updatedAt()).isNotNull();
        assertThat(completedRun.startedAt()).isNotNull();
        assertThat(completedRun.completedAt()).isNotNull();

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED);
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED);
                    assertThat(event.getRunCreated().getWorkflowName()).isEqualTo("test");
                    assertThat(event.getRunCreated().getWorkflowVersion()).isEqualTo(1);
                    assertThat(event.getRunCreated().getConcurrencyKey()).isEqualTo("someConcurrencyKey");
                    assertThat(event.getRunCreated().getPriority()).isEqualTo(6);
                    assertThat(event.getRunCreated().getLabelsMap()).containsOnlyKeys("label-a", "label-b");
                    assertThat(event.getRunCreated().getArgument().hasBinaryContent()).isTrue();
                    assertThat(event.getRunCreated().getArgument().getBinaryContent().getData().toStringUtf8()).isEqualTo("someArgument");
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED);
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(0);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_COMPLETED);
                    assertThat(event.getRunCompleted().getResult().hasBinaryContent()).isTrue();
                    assertThat(event.getRunCompleted().getResult().getBinaryContent().getData().toStringUtf8()).isEqualTo("someResult");
                    assertThat(event.getRunCompleted().hasFailure()).isFalse();
                },
                event -> {
                    assertThat(event.getId()).isEqualTo(-1);
                    assertThat(event.hasTimestamp()).isTrue();

                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED);
                });
    }

    @Test
    void shouldFailWorkflowRunWhenRunnerThrows() {
        registerWorkflow("test", (_, _) -> {
            throw new IllegalStateException("Ouch!");
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        final WorkflowRunMetadata failedRun = awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(failedRun.customStatus()).isNull();
        assertThat(failedRun.concurrencyKey()).isNull();
        assertThat(failedRun.priority()).isZero();
        assertThat(failedRun.labels()).isNull();
        assertThat(failedRun.createdAt()).isNotNull();
        assertThat(failedRun.updatedAt()).isNotNull();
        assertThat(failedRun.startedAt()).isNotNull();
        assertThat(failedRun.completedAt()).isNotNull();

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().hasResult()).isFalse();
                    assertThat(event.getRunCompleted().getFailure().getMessage()).isEqualTo("Ouch!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldFailWorkflowRunOnNonDeterministicExecution() {
        final var executionCounter = new AtomicInteger(0);

        registerWorkflow("test", (ctx, _) -> {
            if (executionCounter.incrementAndGet() == 1) {
                ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            } else {
                ctx.callActivity("def", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            }
            return null;
        });
        registerActivity("abc", (_, _) -> null);
        registerActivity("def", (_, _) -> null);
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 1);

        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                event -> {
                    assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(event.getRunCompleted().getFailure().getMessage()).startsWith("Detected non-deterministic workflow execution");
                },
                event -> assertThat(event.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldFailWorkflowRunWhenCancelled() {
        registerWorkflow("test", (ctx, _) -> {
            // Sleep for a moment so we get an opportunity to cancel the run.
            ctx.createTimer("sleep", Duration.ofSeconds(5)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        engine.requestRunCancellation(runId, "Stop it!");

        final WorkflowRunMetadata canceledRun = awaitRunStatus(runId, WorkflowRunStatus.CANCELLED);

        assertThat(canceledRun.customStatus()).isNull();
        assertThat(canceledRun.concurrencyKey()).isNull();
        assertThat(canceledRun.priority()).isZero();
        assertThat(canceledRun.labels()).isNull();
        assertThat(canceledRun.createdAt()).isNotNull();
        assertThat(canceledRun.updatedAt()).isNotNull();
        assertThat(canceledRun.startedAt()).isNotNull();
        assertThat(canceledRun.completedAt()).isNotNull();

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CANCELED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_CANCELLED);
                    assertThat(entry.getRunCompleted().hasResult()).isFalse();
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).isEqualTo("Stop it!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldWaitForTimerToElapse() {
        registerWorkflow("test", (ctx, _) -> {
            ctx.createTimer("Sleep", Duration.ofMillis(5)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED);
                    assertThat(entry.getTimerCreated().getName()).isEqualTo("Sleep");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldWaitForMultipleTimersToElapse() {
        registerWorkflow("test", (ctx, _) -> {
            final var timers = new ArrayList<Awaitable<Void>>(3);
            for (int i = 0; i < 3; i++) {
                timers.add(ctx.createTimer("sleep" + i, Duration.ofMillis(5)));
            }

            for (final Awaitable<Void> timer : timers) {
                timer.await();
            }

            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(10));

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId).withLimit(15))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldWaitForChildRun() {
        registerWorkflow("foo", (ctx, _) -> {
            final String childWorkflowResult =
                    ctx.callChildWorkflow("bar", 1, null, WORKFLOW_TASK_QUEUE, null, "inputValue", stringConverter(), stringConverter()).await();
            assertThat(childWorkflowResult).contains("inputValue-outputValue");
            return null;
        });
        registerWorkflow("bar", stringConverter(), stringConverter(), (_, arg) -> arg + "-outputValue");
        registerWorkflowWorker("workflow-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldFailWhenChildRunFails() {
        registerWorkflow("foo", (ctx, _) -> {
            ctx.callChildWorkflow("bar", 1, null, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("bar", (_, _) -> {
            throw new IllegalStateException("Oh no!");
        });
        registerWorkflowWorker("workflow-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_FAILED);
                    assertThat(entry.getChildRunFailed().getFailure().getMessage()).isEqualTo("Oh no!");
                },
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).matches("Run .+ of child workflow bar v1 failed");
                    assertThat(entry.getRunCompleted().getFailure().getCause().getMessage()).isEqualTo("Oh no!");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldCancelChildRunsRecursivelyWhenParentRunIsCancelled() {
        final var childRunIdReference = new AtomicReference<UUID>();
        final var grandChildRunIdReference = new AtomicReference<UUID>();

        registerWorkflow("parent", (ctx, _) -> {
            ctx.callChildWorkflow("child", 1, null, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("child", (ctx, _) -> {
            childRunIdReference.set(ctx.runId());
            ctx.callChildWorkflow("grand-child", 1, null, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("grand-child", (ctx, _) -> {
            grandChildRunIdReference.set(ctx.runId());
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 3);
        engine.start();

        final UUID parentRunId = engine.createRun(new CreateWorkflowRunRequest<>("parent", 1));

        await("Grand Child Workflow Run Start")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> assertThat(grandChildRunIdReference.get()).isNotNull());

        engine.requestRunCancellation(parentRunId, "someReason");

        awaitRunStatus(parentRunId, WorkflowRunStatus.CANCELLED);
        awaitRunStatus(childRunIdReference.get(), WorkflowRunStatus.CANCELLED);
        awaitRunStatus(grandChildRunIdReference.get(), WorkflowRunStatus.CANCELLED);
    }

    @Test
    void shouldThrowWhenCancellingRunInTerminalState() {
        registerWorkflow("test", (_, _) -> null);
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunCancellation(runId, "someReason"))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldSuspendAndResumeRunWhenRequested() {
        registerWorkflow("test", (ctx, _) -> {
            // Block for a moment so we get an opportunity to suspend the run.
            ctx.waitForExternalEvent("foo", voidConverter(), Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.sendExternalEvent(new ExternalEvent(runId, "foo", null)).join();
        engine.requestRunResumption(runId);

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
    }

    @Test
    void shouldCancelSuspendedRunWhenRequested() {
        registerWorkflow("test", (ctx, _) -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        engine.requestRunCancellation(runId, "someReason");

        awaitRunStatus(runId, WorkflowRunStatus.CANCELLED);
    }

    @Test
    void shouldThrowWhenSuspendingRunInTerminalState() {
        registerWorkflow("test", (_, _) -> null);
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunSuspension(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Test
    void shouldThrowWhenSuspendingRunInSuspendedState() {
        registerWorkflow("test", (ctx, _) -> {
            // Sleep for a moment so we get an opportunity to suspend the run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        engine.requestRunSuspension(runId);

        awaitRunStatus(runId, WorkflowRunStatus.SUSPENDED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunSuspension(runId))
                .withMessageMatching("Workflow run .+ is already suspended");
    }

    @Test
    void shouldThrowWhenResumingRunInNonSuspendedState() {
        registerWorkflow("test", (ctx, _) -> {
            // Sleep for a moment so we get an opportunity to act on the running run.
            ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.RUNNING);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunResumption(runId))
                .withMessageMatching("Workflow run .+ can not be resumed because it is not suspended");
    }

    @Test
    void shouldThrowWhenResumingRunInTerminalState() {
        registerWorkflow("test", (_, _) -> null);
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThatExceptionOfType(IllegalStateException.class)
                .isThrownBy(() -> engine.requestRunResumption(runId))
                .withMessageMatching("Workflow run .+ is already in terminal status");
    }

    @Nested
    class WorkflowInstanceIdTest {

        @Test
        void shouldNotCreateRunWhenAnotherRunWithSameInstanceIdIsInProgress() {
            registerWorkflow("test", stringConverter(), voidConverter(), (_, _) -> null);

            UUID runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("test", 1)
                            .withWorkflowInstanceId("instanceId"));
            assertThat(runId).isNotNull();

            runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("test", 1)
                            .withWorkflowInstanceId("instanceId"));
            assertThat(runId).isNull();
        }

        @Test
        void shouldFailChildWorkflowWhenRunSameInstanceIdIsInProgress() {
            registerWorkflow("parent", (ctx, _) -> {
                ctx.callChildWorkflow("child", 1, "instanceId", WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
                return null;
            });
            registerWorkflow("child", (ctx, _) -> {
                ctx.createTimer("sleep", Duration.ofSeconds(3)).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 2);
            engine.start();

            final UUID childRunId = engine.createRun(
                    new CreateWorkflowRunRequest<>("child", 1)
                            .withWorkflowInstanceId("instanceId"));
            awaitRunStatus(childRunId, WorkflowRunStatus.RUNNING);

            final UUID parentRunId = engine.createRun(
                    new CreateWorkflowRunRequest<>("parent", 1));
            awaitRunStatus(parentRunId, WorkflowRunStatus.FAILED);

            final Stream<WorkflowEvent> historyEvents = engine
                    .listRunHistory(new ListWorkflowRunHistoryRequest(parentRunId))
                    .items()
                    .stream()
                    .map(WorkflowRunHistoryEntry::event);
            assertThat(historyEvents).satisfiesExactly(
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_CREATED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                    entry -> {
                        assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_FAILED);
                        assertThat(entry.getChildRunFailed().getFailure().hasInternalFailureDetails()).isTrue();
                        assertThat(entry.getChildRunFailed().getFailure().getMessage()).isEqualTo(
                                "Another run already exists in non-terminal state for instance ID: instanceId");
                    },
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
        }

    }

    @Nested
    class ConcurrencyKeyTest {

        @Test
        void shouldExecuteRunsWithSameConcurrencyKeyInPriorityOrder() {
            final var executionQueue = new ArrayBlockingQueue<String>(5);

            registerWorkflow("test", stringConverter(), voidConverter(), (_, arg) -> {
                executionQueue.add(arg);
                return null;
            });
            registerWorkflowWorker("workflow-worker", 5);
            engine.start();

            final var concurrencyKey = "concurrencyKey";

            final List<CreateWorkflowRunResponse> responses = engine.createRuns(
                    Stream.of(1, 2, 3, 4, 5)
                            .<CreateWorkflowRunRequest<?>>map(
                                    number -> new CreateWorkflowRunRequest<>("test", 1)
                                            .withConcurrencyKey(concurrencyKey)
                                            .withPriority(number)
                                            .withArgument(String.valueOf(number)))
                            .toList());

            for (final var response : responses) {
                awaitRunStatus(response.runId(), WorkflowRunStatus.COMPLETED, Duration.ofSeconds(5));
            }

            assertThat(executionQueue).containsExactly("5", "4", "3", "2", "1");
        }

    }

    @Test
    void shouldWaitForExternalEvent() throws Exception {
        registerWorkflow("test", (ctx, _) -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofSeconds(30)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        await("Update")
                .atMost(Duration.ofSeconds(5))
                .untilAsserted(() -> {
                    final WorkflowRunMetadata run = engine.getRunMetadataById(runId);
                    assertThat(run.updatedAt()).isNotNull();
                });

        engine.sendExternalEvent(new ExternalEvent(runId, "foo-123", null)).get(1, TimeUnit.SECONDS);

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.EXTERNAL_EVENT_RECEIVED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldFailWhenWaitingForExternalEventTimesOut() {
        registerWorkflow("test", (ctx, _) -> {
            ctx.waitForExternalEvent("foo-123", voidConverter(), Duration.ofMillis(5)).await();
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                    assertThat(entry.getRunCompleted().getFailure().getMessage()).isEqualTo("Timed out while waiting for external event");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Nested
    class SideEffectTest {

        @Test
        void shouldRecordSideEffectResult() {
            final var sideEffectInvocationCounter = new AtomicInteger();

            registerWorkflow("test", (ctx, _) -> {
                ctx.executeSideEffect("sideEffect", sideEffectInvocationCounter::incrementAndGet).await();

                ctx.createTimer("sleep", Duration.ofMillis(10)).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

            awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

            assertThat(sideEffectInvocationCounter.get()).isEqualTo(1);

            final Stream<WorkflowEvent> historyEvents = engine
                    .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                    .items()
                    .stream()
                    .map(WorkflowRunHistoryEntry::event);
            assertThat(historyEvents).satisfiesExactly(
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                    entry -> {
                        assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.SIDE_EFFECT_EXECUTED);
                        assertThat(entry.getSideEffectExecuted().getName()).isEqualTo("sideEffect");
                    },
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_CREATED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.TIMER_ELAPSED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
        }

        @Test
        void shouldNotAllowNestedSideEffects() {
            registerWorkflow("test", (ctx, _) -> {
                ctx.executeSideEffect("outerSideEffect", () -> ctx.executeSideEffect("nestedSideEffect", () -> {
                }).await()).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

            awaitRunStatus(runId, WorkflowRunStatus.FAILED);

            final Stream<WorkflowEvent> historyEvents = engine
                    .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                    .items()
                    .stream()
                    .map(WorkflowRunHistoryEntry::event);
            assertThat(historyEvents).satisfiesExactly(
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                    entry -> {
                        assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                        assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                        assertThat(entry.getRunCompleted().getFailure().hasSideEffectFailureDetails()).isTrue();
                        assertThat(entry.getRunCompleted().getFailure().getCause().hasApplicationFailureDetails()).isTrue();
                        assertThat(entry.getRunCompleted().getFailure().getCause().getMessage()).isEqualTo("Nested side effects are not allowed");
                    },
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
        }

    }

    @Test
    void shouldCallActivity() {
        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("abc", voidConverter(), stringConverter(), (_, _) -> "123");
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldCreateMultipleActivitiesConcurrently() {
        registerWorkflow("test", voidConverter(), stringConverter(), (ctx, _) -> {
            final List<Awaitable<String>> awaitables = List.of(
                    ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, "first", stringConverter(), stringConverter(), RetryPolicy.ofDefault()),
                    ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, "second", stringConverter(), stringConverter(), RetryPolicy.ofDefault()));

            return awaitables.stream()
                    .map(Awaitable::await)
                    .collect(Collectors.joining(", "));
        });
        registerActivity("abc", stringConverter(), stringConverter(), (_, arg) -> arg);
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        // Workflow task events (WORKFLOW_TASK_STARTED, WORKFLOW_TASK_COMPLETED) are
        // non-deterministically interleaved with activity completions. Filter them out
        // to only assert the deterministic event ordering.
        final List<WorkflowEvent> historyEvents = engine
                .listRunHistory(
                        new ListWorkflowRunHistoryRequest(runId)
                                .withLimit(15))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event)
                .filter(event -> event.getSubjectCase() != WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED
                        && event.getSubjectCase() != WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED)
                .toList();
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED));
    }

    @Test
    void shouldRetryFailingActivity() {
        final var retryPolicy = RetryPolicy.ofDefault()
                .withMaxDelay(Duration.ofMillis(10))
                .withMaxAttempts(3);

        registerWorkflow("test", (ctx, arg) -> {
            ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), retryPolicy).await();
            return null;
        });
        registerActivity("abc", voidConverter(), stringConverter(), (_, _) -> {
            throw new IllegalStateException();
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId).withLimit(20))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED);
                    assertThat(entry.getActivityTaskFailed().getAttempts()).isEqualTo(3);
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldNotRetryActivityFailingWithTerminalException() {
        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("abc", voidConverter(), stringConverter(), (_, _) -> {
            throw new TerminalApplicationFailureException("Ouch!", null);
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED);
                },
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldFailActivityTerminallyOnArgumentDeserializationError() {
        final PayloadConverter<String> throwingArgumentConverter = new PayloadConverter<>() {
            @Override
            public Payload convertToPayload(String value) {
                return stringConverter().convertToPayload(value);
            }

            @Override
            public String convertFromPayload(Payload payload) {
                throw new RuntimeException("boom");
            }
        };

        final var activityInvocations = new AtomicInteger(0);

        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, "input", stringConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("abc", throwingArgumentConverter, stringConverter(), (_, arg) -> {
            activityInvocations.incrementAndGet();
            return arg;
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(activityInvocations).hasValue(0);

        final List<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId).withLimit(20))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event)
                .toList();
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED);
                    assertThat(entry.getActivityTaskFailed().getAttempts()).isEqualTo(1);
                },
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldFailActivityTerminallyOnResultSerializationError() {
        final PayloadConverter<String> throwingResultConverter = new PayloadConverter<>() {
            @Override
            public Payload convertToPayload(String value) {
                throw new RuntimeException("boom");
            }

            @Override
            public String convertFromPayload(Payload payload) {
                return stringConverter().convertFromPayload(payload);
            }
        };

        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), stringConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("abc", voidConverter(), throwingResultConverter, (_, _) -> "result");
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        final List<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId).withLimit(20))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event)
                .toList();
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_FAILED);
                    assertThat(entry.getActivityTaskFailed().getAttempts()).isEqualTo(1);
                },
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                    assertThat(entry.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Test
    void shouldHeartbeatActivity() {
        final var heartbeatsPerformed = new ArrayBlockingQueue<Boolean>(3);

        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("test", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("test", (ctx, _) -> {
            heartbeatsPerformed.add(ctx.maybeHeartbeat());
            Thread.sleep(3_500);
            heartbeatsPerformed.add(ctx.maybeHeartbeat());
            heartbeatsPerformed.add(ctx.maybeHeartbeat());
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));
        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(heartbeatsPerformed).containsExactly(false, true, false);
    }

    @Test
    void shouldDiscardActivityExecutionWhenLockIsLost() {
        final var invocations = new AtomicInteger();
        final var lockLostObserved = new AtomicBoolean();
        final var successorStarted = new CountDownLatch(1);

        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("test", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });

        engine.registerActivityInternal(
                "test", voidConverter(), voidConverter(), ACTIVITY_TASK_QUEUE, Duration.ofSeconds(1),
                (ctx, _) -> {
                    if (invocations.incrementAndGet() > 1) {
                        successorStarted.countDown();
                        return null;
                    }

                    assertThat(successorStarted.await(30, TimeUnit.SECONDS)).isTrue();

                    try {
                        ctx.maybeHeartbeat();
                    } catch (TaskLockLostException e) {
                        lockLostObserved.set(true);
                        throw e;
                    }

                    return null;
                });
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));
        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        await("Displaced execution to observe the lost lock")
                .untilAsserted(() -> assertThat(lockLostObserved).isTrue());
        assertThat(invocations.get()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void shouldReclaimLongRunningActivityWithoutHeartbeatKeepingAttemptAtOne() {
        // Reproduces multi-worker thrash when an activity outlives its lock timeout
        // without renewing the claim: another worker reclaims the same task attempt
        // while the displaced execution eventually loses the lock.
        final var invocations = new AtomicInteger();
        final var lockLostObserved = new AtomicBoolean();
        final var successorStarted = new CountDownLatch(1);

        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("test", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });

        engine.registerActivityInternal(
                "test", voidConverter(), voidConverter(), ACTIVITY_TASK_QUEUE, Duration.ofSeconds(1),
                (ctx, _) -> {
                    final int invocation = invocations.incrementAndGet();
                    if (invocation == 1) {
                        assertThat(successorStarted.await(30, TimeUnit.SECONDS)).isTrue();
                        try {
                            ctx.maybeHeartbeat();
                        } catch (TaskLockLostException e) {
                            lockLostObserved.set(true);
                            throw e;
                        }
                        return null;
                    }

                    successorStarted.countDown();
                    return null;
                });
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));
        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        await("Displaced execution to observe the lost lock")
                .untilAsserted(() -> assertThat(lockLostObserved).isTrue());
        // Same activity attempt is reclaimed by another worker rather than retried
        // as a new attempt after terminal failure.
        assertThat(invocations.get()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void shouldKeepSingleExecutionWhenLongRunningActivityHeartbeats() {
        final var invocations = new AtomicInteger();
        final var heartbeatsEmitted = new AtomicInteger();

        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("test", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });

        engine.registerActivityInternal(
                "test", voidConverter(), voidConverter(), ACTIVITY_TASK_QUEUE, Duration.ofSeconds(1),
                (ctx, _) -> {
                    invocations.incrementAndGet();
                    // Outlive the initial lock window while renewing via heartbeats.
                    final Instant end = Instant.now().plusSeconds(3);
                    while (Instant.now().isBefore(end)) {
                        if (ctx.maybeHeartbeat()) {
                            heartbeatsEmitted.incrementAndGet();
                        }
                        Thread.sleep(200);
                    }
                    return null;
                });
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));
        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(invocations.get()).isEqualTo(1);
        assertThat(heartbeatsEmitted.get()).isPositive();
    }

    @Test
    void shouldCancelActivitiesDuringGracefulShutdown() throws Exception {
        final var activityStarted = new AtomicBoolean(false);
        final var activityInterrupted = new AtomicBoolean(false);

        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("test", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("test", (_, _) -> {
            activityStarted.set(true);
            try {
                Thread.sleep(Duration.ofMinutes(1));
            } catch (InterruptedException e) {
                activityInterrupted.set(true);
                throw e;
            }
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 1);
        engine.start();

        engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        await("Activity start")
                .atMost(Duration.ofSeconds(3))
                .until(activityStarted::get);

        engine.close();

        assertThat(activityInterrupted).isTrue();
    }

    @Test
    void shouldAbandonActivityInterruptedDuringShutdownInsteadOfFailingIt() throws Exception {
        final var activityStarted = new AtomicBoolean(false);
        final var activityBlockedLatch = new CountDownLatch(1);

        registerWorkflow("test", (ctx, _) -> {
            ctx.callActivity("test", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("test", (_, _) -> {
            activityStarted.set(true);
            try {
                activityBlockedLatch.await(1, TimeUnit.MINUTES);
            } catch (InterruptedException e) {
                throw new IllegalStateException("Interrupted", e);
            }
            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        registerTaskWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        await("Activity start")
                .atMost(Duration.ofSeconds(3))
                .until(activityStarted::get);

        engine.close();
        
        final Integer attempt = Jdbi.create(dataSource).withHandle(handle -> handle
                .createQuery("SELECT attempt FROM dex_activity_task WHERE workflow_run_id = :runId")
                .bind("runId", runId)
                .mapTo(Integer.class)
                .one());
        assertThat(attempt).isEqualTo(1);
    }

    @Test
    void shouldPropagateExceptions() {
        final AtomicReference<FailureException> exceptionReference = new AtomicReference<>();

        registerWorkflow("foo", (ctx, _) -> {
            try {
                ctx.callChildWorkflow("bar", 1, null, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            } catch (FailureException e) {
                exceptionReference.set(e);
                throw e;
            }

            return null;
        });
        registerWorkflow("bar", (ctx, _) -> {
            ctx.callChildWorkflow("baz", 1, null, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("baz", (ctx, _) -> {
            ctx.callActivity("qux", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
            return null;
        });
        registerActivity("qux", (_, _) -> {
            throw new TerminalApplicationFailureException("Ouch!", null);
        });
        registerWorkflowWorker("workflow-worker", 3);
        registerTaskWorker("activity-worker", 1);
        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1)
                .withLabels(Map.of("oof", "rab")));

        awaitRunStatus(runId, WorkflowRunStatus.FAILED, Duration.ofSeconds(15));

        assertThat(exceptionReference.get()).satisfies(e -> {
            assertThat(e).isInstanceOf(ChildWorkflowFailureException.class);
            assertThat(e.getMessage()).matches("Run .+ of child workflow bar v1 failed");
            assertThat(e.getStackTrace()).isEmpty();

            {
                final var failure = (ChildWorkflowFailureException) e;
                assertThat(failure.getRunId()).isNotNull();
                assertThat(failure.getWorkflowName()).isEqualTo("bar");
                assertThat(failure.getWorkflowVersion()).isEqualTo(1);
            }

            assertThat(e.getCause()).satisfies(firstCause -> {
                assertThat(firstCause).isInstanceOf(ChildWorkflowFailureException.class);
                assertThat(firstCause.getMessage()).matches("Run .+ of child workflow baz v1 failed");
                assertThat(firstCause.getStackTrace()).isEmpty();

                {
                    final var failure = (ChildWorkflowFailureException) firstCause;
                    assertThat(failure.getRunId()).isNotNull();
                    assertThat(failure.getWorkflowName()).isEqualTo("baz");
                    assertThat(failure.getWorkflowVersion()).isEqualTo(1);
                }

                assertThat(firstCause.getCause()).satisfies(secondCause -> {
                    assertThat(secondCause).isInstanceOf(ActivityFailureException.class);
                    assertThat(secondCause.getMessage()).isEqualTo("Activity qux failed");
                    assertThat(secondCause.getStackTrace()).isEmpty();

                    {
                        final var failure = (ActivityFailureException) secondCause;
                        assertThat(failure.getActivityName()).isEqualTo("qux");
                    }

                    assertThat(secondCause.getCause()).satisfies(thirdCause -> {
                        assertThat(thirdCause).isInstanceOf(ApplicationFailureException.class);
                        assertThat(thirdCause.getMessage()).isEqualTo("Ouch!");
                        assertThat(thirdCause.getStackTrace()).isNotEmpty();
                        assertThat(thirdCause.getCause()).isNull();

                        {
                            final var failure = (ApplicationFailureException) thirdCause;
                            assertThat(failure.isTerminal()).isTrue();
                        }
                    });
                });
            });
        });
    }

    @Test
    void shouldPropagateLabels() {
        registerWorkflow("foo", (ctx, _) -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            ctx.callChildWorkflow("bar", 1, null, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter()).await();
            return null;
        });
        registerWorkflow("bar", (ctx, _) -> {
            assertThat(ctx.labels()).containsOnlyKeys("oof", "rab");
            return null;
        });
        registerWorkflowWorker("workflow-worker", 2);
        engine.start();

        final UUID runId = engine.createRun(
                new CreateWorkflowRunRequest<>("foo", 1)
                        .withLabels(Map.of("oof", "123", "rab", "321")));

        awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final Stream<WorkflowEvent> historyEvents = engine
                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                .items()
                .stream()
                .map(WorkflowRunHistoryEntry::event);
        assertThat(historyEvents).satisfiesExactly(
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED);
                    assertThat(entry.getRunCreated().getLabelsMap()).containsOnlyKeys("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                entry -> {
                    assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_CREATED);
                    assertThat(entry.getChildRunCreated().getLabelsMap()).containsOnlyKeys("oof", "rab");
                },
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.CHILD_RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED),
                entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
    }

    @Nested
    class ContinueAsNewTest {

        @Test
        void shouldContinueAsNew() {
            registerWorkflow("foo", stringConverter(), stringConverter(), (ctx, arg) -> {
                final int iteration = Integer.parseInt(arg);
                ctx.callActivity("abc", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault()).await();
                if (iteration < 3) {
                    ctx.continueAsNew(
                            new ContinueAsNewOptions<String>()
                                    .withArgument(String.valueOf(iteration + 1)));
                }
                return String.valueOf(iteration);
            });
            registerActivity("abc", (_, _) -> null);
            registerWorkflowWorker("workflow-worker", 1);
            registerTaskWorker("activity-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("foo", 1)
                            .withArgument("0"));

            awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

            final Stream<WorkflowEvent> historyEvents = engine
                    .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                    .items()
                    .stream()
                    .map(WorkflowRunHistoryEntry::event);
            assertThat(historyEvents).satisfiesExactly(
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                    entry -> {
                        assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_CREATED);
                        assertThat(stringConverter().convertFromPayload(entry.getRunCreated().getArgument())).isEqualTo("3");
                    },
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_STARTED),
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.ACTIVITY_TASK_COMPLETED),
                    entry -> {
                        assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.RUN_COMPLETED);
                        assertThat(stringConverter().convertFromPayload(entry.getRunCompleted().getResult())).isEqualTo("3");
                    },
                    entry -> assertThat(entry.getSubjectCase()).isEqualTo(WorkflowEvent.SubjectCase.WORKFLOW_TASK_COMPLETED));
        }

        @Test
        void shouldFailContinueAsNewWhenActivityTaskPending() {
            registerWorkflow("foo", stringConverter(), stringConverter(), (ctx, _) -> {
                ctx.callActivity("blocked", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault());
                ctx.waitForExternalEvent("go", voidConverter(), Duration.ofMinutes(5)).await();
                ctx.continueAsNew(new ContinueAsNewOptions<String>().withArgument("next"));
                return null;
            });
            registerActivity("blocked", (_, _) -> null);
            registerWorkflowWorker("workflow-worker", 1);
            // No activity worker registered, so the activity task remains persisted but unprocessed.
            engine.start();

            final UUID runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("foo", 1).withArgument("0"));

            await("Activity task to be created")
                    .atMost(Duration.ofSeconds(30))
                    .untilAsserted(() -> {
                        final Stream<WorkflowEvent> events = engine
                                .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                                .items()
                                .stream()
                                .map(WorkflowRunHistoryEntry::event);
                        assertThat(events).anyMatch(
                                event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.ACTIVITY_TASK_CREATED);
                    });

            engine.sendExternalEvent(new ExternalEvent(runId, "go", null)).join();

            awaitRunStatus(runId, WorkflowRunStatus.FAILED);

            final Stream<WorkflowEvent> historyEvents = engine
                    .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                    .items()
                    .stream()
                    .map(WorkflowRunHistoryEntry::event);
            assertThat(historyEvents)
                    .filteredOn(event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.RUN_COMPLETED)
                    .singleElement()
                    .satisfies(event -> {
                        assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                        assertThat(event.getRunCompleted().getFailure().getMessage())
                                .contains("continueAsNew is not allowed while activity tasks, child runs, or timers are still pending");
                    });
        }

        @Test
        void shouldFailContinueAsNewWhenChildRunPending() {
            final var childRunIdRef = new AtomicReference<UUID>();
            registerWorkflow("parent", stringConverter(), stringConverter(), (ctx, _) -> {
                final Awaitable<Void> childAwaitable = ctx.callChildWorkflow(
                        "child", 1, null, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter());
                ctx.waitForExternalEvent("go", voidConverter(), Duration.ofMinutes(5)).await();
                ctx.continueAsNew(new ContinueAsNewOptions<String>().withArgument("next"));
                childAwaitable.await();
                return null;
            });
            registerWorkflow("child", (ctx, _) -> {
                childRunIdRef.compareAndSet(null, ctx.runId());
                ctx.waitForExternalEvent("never", voidConverter(), Duration.ofMinutes(5)).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 2);
            engine.start();

            final UUID parentRunId = engine.createRun(
                    new CreateWorkflowRunRequest<>("parent", 1).withArgument("0"));

            await("Child run to be created")
                    .atMost(Duration.ofSeconds(30))
                    .untilAsserted(() -> {
                        final Stream<WorkflowEvent> events = engine
                                .listRunHistory(new ListWorkflowRunHistoryRequest(parentRunId))
                                .items()
                                .stream()
                                .map(WorkflowRunHistoryEntry::event);
                        assertThat(events).anyMatch(
                                event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.CHILD_RUN_CREATED);
                    });
            await("Child run to start")
                    .atMost(Duration.ofSeconds(30))
                    .until(() -> childRunIdRef.get() != null);

            engine.sendExternalEvent(new ExternalEvent(parentRunId, "go", null)).join();

            awaitRunStatus(parentRunId, WorkflowRunStatus.FAILED);

            final Stream<WorkflowEvent> historyEvents = engine
                    .listRunHistory(new ListWorkflowRunHistoryRequest(parentRunId))
                    .items()
                    .stream()
                    .map(WorkflowRunHistoryEntry::event);
            assertThat(historyEvents)
                    .filteredOn(event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.RUN_COMPLETED)
                    .singleElement()
                    .satisfies(event -> {
                        assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                        assertThat(event.getRunCompleted().getFailure().getMessage())
                                .contains("continueAsNew is not allowed while activity tasks, child runs, or timers are still pending");
                    });

            // Parent terminal-cleanup must propagate cancellation to the child.
            awaitRunStatus(childRunIdRef.get(), WorkflowRunStatus.CANCELLED);
        }

        @Test
        void shouldFailContinueAsNewWhenActivityTaskScheduledWithoutAwait() {
            registerWorkflow("foo", stringConverter(), stringConverter(), (ctx, _) -> {
                ctx.callActivity("blocked", ACTIVITY_TASK_QUEUE, null, voidConverter(), voidConverter(), RetryPolicy.ofDefault());
                ctx.continueAsNew(new ContinueAsNewOptions<String>().withArgument("next"));
                return null;
            });
            registerActivity("blocked", (_, _) -> null);
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("foo", 1).withArgument("0"));

            awaitRunStatus(runId, WorkflowRunStatus.FAILED);

            final Stream<WorkflowEvent> historyEvents = engine
                    .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                    .items()
                    .stream()
                    .map(WorkflowRunHistoryEntry::event);
            assertThat(historyEvents)
                    .filteredOn(event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.RUN_COMPLETED)
                    .singleElement()
                    .satisfies(event -> {
                        assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                        assertThat(event.getRunCompleted().getFailure().getMessage())
                                .contains("continueAsNew is not allowed while activity tasks, child runs, or timers are still pending");
                    });
        }

        @Test
        void shouldFailContinueAsNewWhenTimerScheduledWithoutAwait() {
            registerWorkflow("foo", stringConverter(), stringConverter(), (ctx, _) -> {
                ctx.createTimer("long", Duration.ofMinutes(5));
                ctx.continueAsNew(new ContinueAsNewOptions<String>().withArgument("next"));
                return null;
            });
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("foo", 1).withArgument("0"));

            awaitRunStatus(runId, WorkflowRunStatus.FAILED);

            final Stream<WorkflowEvent> historyEvents = engine
                    .listRunHistory(new ListWorkflowRunHistoryRequest(runId))
                    .items()
                    .stream()
                    .map(WorkflowRunHistoryEntry::event);
            assertThat(historyEvents)
                    .filteredOn(event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.RUN_COMPLETED)
                    .singleElement()
                    .satisfies(event -> {
                        assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                        assertThat(event.getRunCompleted().getFailure().getMessage())
                                .contains("continueAsNew is not allowed while activity tasks, child runs, or timers are still pending");
                    });
        }

        @Test
        void shouldFailContinueAsNewWhenChildRunScheduledWithoutAwait() {
            registerWorkflow("parent", stringConverter(), stringConverter(), (ctx, _) -> {
                ctx.callChildWorkflow("child", 1, null, WORKFLOW_TASK_QUEUE, null, null, voidConverter(), voidConverter());
                ctx.continueAsNew(new ContinueAsNewOptions<String>().withArgument("next"));
                return null;
            });
            registerWorkflow("child", (ctx, _) -> {
                ctx.waitForExternalEvent("never", voidConverter(), Duration.ofMinutes(5)).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 2);
            engine.start();

            final UUID parentRunId = engine.createRun(
                    new CreateWorkflowRunRequest<>("parent", 1).withArgument("0"));

            awaitRunStatus(parentRunId, WorkflowRunStatus.FAILED);

            final Stream<WorkflowEvent> historyEvents = engine
                    .listRunHistory(new ListWorkflowRunHistoryRequest(parentRunId))
                    .items()
                    .stream()
                    .map(WorkflowRunHistoryEntry::event);
            assertThat(historyEvents)
                    .filteredOn(event -> event.getSubjectCase() == WorkflowEvent.SubjectCase.RUN_COMPLETED)
                    .singleElement()
                    .satisfies(event -> {
                        assertThat(event.getRunCompleted().getStatus()).isEqualTo(WORKFLOW_RUN_STATUS_FAILED);
                        assertThat(event.getRunCompleted().getFailure().getMessage())
                                .contains("continueAsNew is not allowed while activity tasks, child runs, or timers are still pending");
                    });
        }

    }

    @Test
    void shouldInformEventListenersAboutCompletedRuns() {
        final var completedRuns = new ArrayList<WorkflowRunMetadata>();
        engine.addEventListener((WorkflowRunsCompletedEventListener) event -> {
            completedRuns.addAll(event.completedRuns());
        });

        registerWorkflow("foo", stringConverter(), stringConverter(), (_, arg) -> {
            final boolean shouldFail = Boolean.parseBoolean(arg);
            if (shouldFail) {
                throw new IllegalStateException();
            }

            return null;
        });
        registerWorkflowWorker("workflow-worker", 1);
        engine.start();

        final UUID succeedingRunId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1).withArgument("false"));
        final UUID failingRunId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1).withArgument("true"));

        awaitRunStatus(succeedingRunId, WorkflowRunStatus.COMPLETED);
        awaitRunStatus(failingRunId, WorkflowRunStatus.FAILED);

        await("Run completion events")
                .atMost(1, TimeUnit.SECONDS)
                .untilAsserted(() -> assertThat(completedRuns).hasSize(2));

        assertThat(completedRuns).satisfiesExactlyInAnyOrder(
                run -> {
                    assertThat(run.id()).isEqualTo(succeedingRunId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                },
                run -> {
                    assertThat(run.id()).isEqualTo(failingRunId);
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.FAILED);
                });
    }

    @Test
    void shouldSupportWorkflowVersioning() {
        // TODO
    }

    @Test
    void shouldListRuns() {
        registerWorkflow("test", (_, _) -> null);

        for (int i = 0; i < 10; i++) {
            engine.createRun(new CreateWorkflowRunRequest<>("test", 1));
        }

        Page<WorkflowRunMetadata> runsPage = engine.listRuns(
                new ListWorkflowRunsRequest()
                        .withLimit(5));
        assertThat(runsPage.items()).hasSize(5);
        assertThat(runsPage.nextPageToken()).isNotNull();

        runsPage = engine.listRuns(
                new ListWorkflowRunsRequest()
                        .withPageToken(runsPage.nextPageToken())
                        .withLimit(5));
        assertThat(runsPage.items()).hasSize(5);
        assertThat(runsPage.nextPageToken()).isNull();
    }

    @Test
    void shouldListRunsFilteredByLabels() {
        registerWorkflow("test", (_, _) -> null);

        engine.createRun(new CreateWorkflowRunRequest<>("test", 1)
                .withLabels(Map.of("env", "prod", "team", "api")));
        engine.createRun(new CreateWorkflowRunRequest<>("test", 1)
                .withLabels(Map.of("env", "prod", "team", "web")));
        engine.createRun(new CreateWorkflowRunRequest<>("test", 1)
                .withLabels(Map.of("env", "dev", "team", "api")));
        engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

        assertThat(engine.listRuns(
                new ListWorkflowRunsRequest()
                        .withLabels(Map.of("env", "prod"))).items())
                .hasSize(2);

        assertThat(engine.listRuns(
                new ListWorkflowRunsRequest()
                        .withLabels(Map.of("env", "prod", "team", "api"))).items())
                .hasSize(1);

        assertThat(engine.listRuns(
                new ListWorkflowRunsRequest()
                        .withLabels(Map.of("env", "staging"))).items())
                .isEmpty();
    }

    @Nested
    class ExistsRunTest {

        @Test
        void shouldReturnTrueWhenRunExistsWithMatchingStatus() {
            registerWorkflow("test", (_, _) -> null);
            engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

            assertThat(engine.existsRun(new ExistsWorkflowRunRequest(
                    Set.of(WorkflowRunStatus.CREATED), null))).isTrue();
        }

        @Test
        void shouldReturnFalseWhenNoRunExistsWithMatchingStatus() {
            registerWorkflow("test", (_, _) -> null);
            engine.createRun(new CreateWorkflowRunRequest<>("test", 1));

            assertThat(engine.existsRun(new ExistsWorkflowRunRequest(
                    Set.of(WorkflowRunStatus.COMPLETED), null))).isFalse();
        }

        @Test
        void shouldReturnTrueWhenRunExistsWithMatchingLabels() {
            registerWorkflow("test", (_, _) -> null);
            engine.createRun(new CreateWorkflowRunRequest<>("test", 1)
                    .withLabels(Map.of("foo", "bar")));

            assertThat(engine.existsRun(new ExistsWorkflowRunRequest(
                    null, Map.of("foo", "bar")))).isTrue();
        }

        @Test
        void shouldReturnFalseWhenNoRunExistsWithMatchingLabels() {
            registerWorkflow("test", (_, _) -> null);
            engine.createRun(new CreateWorkflowRunRequest<>("test", 1)
                    .withLabels(Map.of("foo", "bar")));

            assertThat(engine.existsRun(new ExistsWorkflowRunRequest(
                    null, Map.of("foo", "baz")))).isFalse();
        }

        @Test
        void shouldReturnTrueWhenRunExistsWithMatchingStatusAndLabels() {
            registerWorkflow("test", (_, _) -> null);
            engine.createRun(new CreateWorkflowRunRequest<>("test", 1)
                    .withLabels(Map.of("foo", "bar")));

            assertThat(engine.existsRun(new ExistsWorkflowRunRequest(
                    Set.of(WorkflowRunStatus.CREATED), Map.of("foo", "bar")))).isTrue();
        }

        @Test
        void shouldReturnFalseWhenRunExistsWithMatchingStatusButNotLabels() {
            registerWorkflow("test", (_, _) -> null);
            engine.createRun(new CreateWorkflowRunRequest<>("test", 1)
                    .withLabels(Map.of("foo", "bar")));

            assertThat(engine.existsRun(new ExistsWorkflowRunRequest(
                    Set.of(WorkflowRunStatus.CREATED), Map.of("foo", "baz")))).isFalse();
        }

    }

    @Nested
    class ListRunHistoryTest {

        @Test
        void shouldListRunHistory() {
            registerWorkflow("foo", (ctx, _) -> {
                ctx.executeSideEffect("a", () -> {
                }).await();
                ctx.executeSideEffect("b", () -> {
                }).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1));

            awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

            Page<WorkflowRunHistoryEntry> historyPage = engine.listRunHistory(
                    new ListWorkflowRunHistoryRequest(runId)
                            .withLimit(3));
            assertThat(historyPage.items()).satisfiesExactly(
                    entry -> assertThat(entry.event().hasWorkflowTaskStarted()).isTrue(),
                    entry -> assertThat(entry.event().hasRunCreated()).isTrue(),
                    entry -> assertThat(entry.event().hasRunStarted()).isTrue());
            assertThat(historyPage.nextPageToken()).isNotNull();

            historyPage = engine.listRunHistory(
                    new ListWorkflowRunHistoryRequest(runId)
                            .withPageToken(historyPage.nextPageToken())
                            .withLimit(2));
            assertThat(historyPage.items()).satisfiesExactly(
                    entry -> assertThat(entry.event().hasSideEffectExecuted()).isTrue(),
                    entry -> assertThat(entry.event().hasSideEffectExecuted()).isTrue());
            assertThat(historyPage.nextPageToken()).isNotNull();
        }

        @Test
        void shouldListRunHistoryInDescOrder() {
            registerWorkflow("foo", (ctx, _) -> {
                ctx.executeSideEffect("a", () -> {
                }).await();
                ctx.executeSideEffect("b", () -> {
                }).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1));

            awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

            Page<WorkflowRunHistoryEntry> historyPage = engine.listRunHistory(
                    new ListWorkflowRunHistoryRequest(runId)
                            .withSortDirection(SortDirection.DESC)
                            .withLimit(3));
            assertThat(historyPage.items()).satisfiesExactly(
                    entry -> assertThat(entry.event().hasWorkflowTaskCompleted()).isTrue(),
                    entry -> assertThat(entry.event().hasRunCompleted()).isTrue(),
                    entry -> assertThat(entry.event().hasSideEffectExecuted()).isTrue());
            assertThat(historyPage.items())
                    .extracting(WorkflowRunHistoryEntry::sequenceNumber)
                    .isSortedAccordingTo(Comparator.reverseOrder());
            assertThat(historyPage.nextPageToken()).isNotNull();

            final int lastSequenceNumberPage1 = historyPage.items().getLast().sequenceNumber();

            historyPage = engine.listRunHistory(
                    new ListWorkflowRunHistoryRequest(runId)
                            .withPageToken(historyPage.nextPageToken())
                            .withLimit(2));
            assertThat(historyPage.items()).satisfiesExactly(
                    entry -> assertThat(entry.event().hasSideEffectExecuted()).isTrue(),
                    entry -> assertThat(entry.event().hasRunStarted()).isTrue());
            assertThat(historyPage.items())
                    .extracting(WorkflowRunHistoryEntry::sequenceNumber)
                    .isSortedAccordingTo(Comparator.reverseOrder())
                    .allSatisfy(seqNo -> assertThat(seqNo).isLessThan(lastSequenceNumberPage1));
            assertThat(historyPage.nextPageToken()).isNotNull();
        }

        @Test
        void shouldListRunHistoryFromSequenceNumber() {
            registerWorkflow("foo", (ctx, _) -> {
                ctx.executeSideEffect("a", () -> {
                }).await();
                ctx.executeSideEffect("b", () -> {
                }).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1));

            awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

            Page<WorkflowRunHistoryEntry> historyPage = engine.listRunHistory(
                    new ListWorkflowRunHistoryRequest(runId)
                            .withLimit(3));
            assertThat(historyPage.items()).satisfiesExactly(
                    entry -> assertThat(entry.event().hasWorkflowTaskStarted()).isTrue(),
                    entry -> assertThat(entry.event().hasRunCreated()).isTrue(),
                    entry -> assertThat(entry.event().hasRunStarted()).isTrue());

            final int lastSeenSequenceNumber = historyPage.items().getLast().sequenceNumber();

            historyPage = engine.listRunHistory(
                    new ListWorkflowRunHistoryRequest(runId)
                            .withFromSequenceNumber(lastSeenSequenceNumber)
                            .withLimit(2));
            assertThat(historyPage.items()).satisfiesExactly(
                    entry -> assertThat(entry.event().hasSideEffectExecuted()).isTrue(),
                    entry -> assertThat(entry.event().hasSideEffectExecuted()).isTrue());
            assertThat(historyPage.nextPageToken()).isNotNull();
        }

        @Test
        void shouldListRunHistoryFromSequenceNumberInDescOrder() {
            registerWorkflow("foo", (ctx, _) -> {
                ctx.executeSideEffect("a", () -> {
                }).await();
                ctx.executeSideEffect("b", () -> {
                }).await();
                return null;
            });
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>("foo", 1));

            awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

            // Get the first 3 events to establish a known sequence number.
            Page<WorkflowRunHistoryEntry> historyPage = engine.listRunHistory(
                    new ListWorkflowRunHistoryRequest(runId)
                            .withLimit(3));
            assertThat(historyPage.items()).satisfiesExactly(
                    entry -> assertThat(entry.event().hasWorkflowTaskStarted()).isTrue(),
                    entry -> assertThat(entry.event().hasRunCreated()).isTrue(),
                    entry -> assertThat(entry.event().hasRunStarted()).isTrue());

            final int lastSeenSequenceNumber = historyPage.items().getLast().sequenceNumber();

            // Use fromSequenceNumber + DESC to get newer events in reverse order (polling use case).
            historyPage = engine.listRunHistory(
                    new ListWorkflowRunHistoryRequest(runId)
                            .withFromSequenceNumber(lastSeenSequenceNumber)
                            .withSortDirection(SortDirection.DESC)
                            .withLimit(2));
            assertThat(historyPage.items()).hasSize(2);
            assertThat(historyPage.items())
                    .extracting(WorkflowRunHistoryEntry::sequenceNumber)
                    .isSortedAccordingTo(Comparator.reverseOrder())
                    .allSatisfy(seqNo -> assertThat(seqNo).isGreaterThan(lastSeenSequenceNumber));
            assertThat(historyPage.nextPageToken()).isNotNull();
        }

    }

    @Nested
    class GetRunMetadataByInstanceIdTest {

        @Test
        void shouldReturnMetadataWhenRunExistsWithNonTerminalState() {
            registerWorkflow("foo", (_, _) -> null);

            final UUID runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("foo", 1)
                            .withWorkflowInstanceId("foo-instance"));
            assertThat(runId).isNotNull();

            final WorkflowRunMetadata runMetadata =
                    engine.getRunMetadataByInstanceId("foo-instance");
            assertThat(runMetadata).isNotNull();
            assertThat(runMetadata.id()).isEqualTo(runId);
        }

        @Test
        void shouldReturnNullWhenRunDoesNotExist() {
            final WorkflowRunMetadata runMetadata =
                    engine.getRunMetadataByInstanceId("doesNotExist");
            assertThat(runMetadata).isNull();
        }

        @Test
        void shouldReturnNullWhenRunExistsWithTerminalState() {
            registerWorkflow("foo", (_, _) -> null);
            registerWorkflowWorker("workflow-worker", 1);
            engine.start();

            final UUID runId = engine.createRun(
                    new CreateWorkflowRunRequest<>("foo", 1)
                            .withWorkflowInstanceId("foo-instance"));
            assertThat(runId).isNotNull();
            awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

            final WorkflowRunMetadata runMetadata =
                    engine.getRunMetadataByInstanceId("foo-instance");
            assertThat(runMetadata).isNull();
        }

    }

    @Nested
    class WorkflowTaskQueueTest {

        @Test
        void createShouldReturnTrueWhenCreatedAndFalseWhenNot() {
            boolean created = engine.createTaskQueue(
                    new CreateTaskQueueRequest(TaskType.WORKFLOW, "foo", 1));
            assertThat(created).isTrue();

            created = engine.createTaskQueue(
                    new CreateTaskQueueRequest(TaskType.WORKFLOW, "foo", 2));
            assertThat(created).isFalse();
        }

        @Test
        void updateShouldReturnTrueWhenUpdated() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "foo", 1));

            final boolean updated = engine.updateTaskQueue(
                    new UpdateTaskQueueRequest(TaskType.WORKFLOW, "foo", TaskQueueStatus.PAUSED, null));
            assertThat(updated).isTrue();
        }

        @Test
        void updateShouldReturnFalseWhenUnchanged() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "foo", 1));

            final boolean updated = engine.updateTaskQueue(
                    new UpdateTaskQueueRequest(TaskType.WORKFLOW, "foo", null, null));
            assertThat(updated).isFalse();
        }

        @Test
        void updateShouldThrowWhenQueueDoesNotExist() {
            assertThatExceptionOfType(NoSuchElementException.class)
                    .isThrownBy(() -> engine.updateTaskQueue(
                            new UpdateTaskQueueRequest(TaskType.WORKFLOW, "does-not-exist", null, null)));
        }

        @Test
        void listShouldSupportPagination() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "foo-1", 1));
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "foo-2", 2));

            Page<@NonNull TaskQueue> queuesPage = engine.listTaskQueues(
                    new ListTaskQueuesRequest(TaskType.WORKFLOW).withLimit(2));
            assertThat(queuesPage.items()).satisfiesExactly(
                    queue -> {
                        assertThat(queue.name()).isEqualTo("default");
                        assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                        assertThat(queue.capacity()).isEqualTo(10);
                        assertThat(queue.depth()).isEqualTo(0);
                        assertThat(queue.createdAt()).isNotNull();
                        assertThat(queue.updatedAt()).isNull();
                    },
                    queue -> {
                        assertThat(queue.name()).isEqualTo("foo-1");
                        assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                        assertThat(queue.capacity()).isEqualTo(1);
                        assertThat(queue.depth()).isEqualTo(0);
                        assertThat(queue.createdAt()).isNotNull();
                        assertThat(queue.updatedAt()).isNull();
                    });
            assertThat(queuesPage.nextPageToken()).isNotNull();

            queuesPage = engine.listTaskQueues(
                    new ListTaskQueuesRequest(TaskType.WORKFLOW).withPageToken(queuesPage.nextPageToken()));
            assertThat(queuesPage.items()).satisfiesExactly(queue -> {
                assertThat(queue.name()).isEqualTo("foo-2");
                assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                assertThat(queue.capacity()).isEqualTo(2);
                assertThat(queue.depth()).isEqualTo(0);
                assertThat(queue.createdAt()).isNotNull();
                assertThat(queue.updatedAt()).isNull();
            });
            assertThat(queuesPage.nextPageToken()).isNull();
        }

    }

    @Nested
    class TaskQueueTest {

        @Test
        void createShouldReturnTrueWhenCreatedAndFalseWhenNot() {
            boolean created = engine.createTaskQueue(
                    new CreateTaskQueueRequest(TaskType.ACTIVITY, "foo", 1));
            assertThat(created).isTrue();

            created = engine.createTaskQueue(
                    new CreateTaskQueueRequest(TaskType.ACTIVITY, "foo", 2));
            assertThat(created).isFalse();
        }

        @Test
        void updateShouldReturnTrueWhenUpdated() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "foo", 1));

            final boolean updated = engine.updateTaskQueue(
                    new UpdateTaskQueueRequest(TaskType.ACTIVITY, "foo", TaskQueueStatus.PAUSED, null));
            assertThat(updated).isTrue();
        }

        @Test
        void updateShouldReturnFalseWhenUnchanged() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "foo", 1));

            final boolean updated = engine.updateTaskQueue(
                    new UpdateTaskQueueRequest(TaskType.ACTIVITY, "foo", null, null));
            assertThat(updated).isFalse();
        }

        @Test
        void updateShouldThrowWhenQueueDoesNotExist() {
            assertThatExceptionOfType(NoSuchElementException.class)
                    .isThrownBy(() -> engine.updateTaskQueue(
                            new UpdateTaskQueueRequest(TaskType.ACTIVITY, "does-not-exist", null, null)));
        }

        @Test
        void listShouldSupportPagination() {
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "foo-1", 1));
            engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "foo-2", 2));

            Page<@NonNull TaskQueue> queuesPage = engine.listTaskQueues(
                    new ListTaskQueuesRequest(TaskType.ACTIVITY).withLimit(2));
            assertThat(queuesPage.items()).satisfiesExactly(
                    queue -> {
                        assertThat(queue.name()).isEqualTo("default");
                        assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                        assertThat(queue.capacity()).isEqualTo(10);
                        assertThat(queue.depth()).isEqualTo(0);
                        assertThat(queue.createdAt()).isNotNull();
                        assertThat(queue.updatedAt()).isNull();
                    },
                    queue -> {
                        assertThat(queue.name()).isEqualTo("foo-1");
                        assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                        assertThat(queue.capacity()).isEqualTo(1);
                        assertThat(queue.depth()).isEqualTo(0);
                        assertThat(queue.createdAt()).isNotNull();
                        assertThat(queue.updatedAt()).isNull();
                    });
            assertThat(queuesPage.nextPageToken()).isNotNull();

            queuesPage = engine.listTaskQueues(
                    new ListTaskQueuesRequest(TaskType.ACTIVITY).withPageToken(queuesPage.nextPageToken()));
            assertThat(queuesPage.items()).satisfiesExactly(queue -> {
                assertThat(queue.name()).isEqualTo("foo-2");
                assertThat(queue.status()).isEqualTo(TaskQueueStatus.ACTIVE);
                assertThat(queue.capacity()).isEqualTo(2);
                assertThat(queue.depth()).isEqualTo(0);
                assertThat(queue.createdAt()).isNotNull();
                assertThat(queue.updatedAt()).isNull();
            });
            assertThat(queuesPage.nextPageToken()).isNull();
        }

    }

    @Nested
    class HealthProbeTest {

        @Test
        void shouldReportAsUpWhenRunning() {
            engine.start();

            final HealthCheckResponse response = engine.probeHealth();

            assertThat(response).isNotNull();
            assertThat(response.getName()).isEqualTo("dex-engine");
            assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.UP);
            assertThat(response.getData()).isPresent();
            assertThat(response.getData().get()).containsExactlyInAnyOrderEntriesOf(
                    Map.ofEntries(
                            Map.entry("internalStatus", "RUNNING"),
                            Map.entry("buffer:activity-task-heartbeat", "RUNNING"),
                            Map.entry("buffer:external-event", "RUNNING"),
                            Map.entry("buffer:task-event", "RUNNING")));
        }

        @Test
        void shouldReportAsDownWhenCreated() {
            final HealthCheckResponse response = engine.probeHealth();

            assertThat(response).isNotNull();
            assertThat(response.getName()).isEqualTo("dex-engine");
            assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
            assertThat(response.getData()).isPresent();
            assertThat(response.getData().get()).containsExactlyInAnyOrderEntriesOf(Map.of("internalStatus", "CREATED"));
        }

        @Test
        void shouldReportAsDownWhenStopped() throws Exception {
            engine.start();
            engine.close();

            final HealthCheckResponse response = engine.probeHealth();

            assertThat(response).isNotNull();
            assertThat(response.getName()).isEqualTo("dex-engine");
            assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
            assertThat(response.getData()).isPresent();
            assertThat(response.getData().get()).containsExactlyInAnyOrderEntriesOf(Map.of("internalStatus", "STOPPED"));
        }

    }

    private interface InternalWorkflow<A, R> extends Workflow<A, R> {

        R execute(WorkflowContextImpl<A, R> ctx, A argument);

        @Override
        default R execute(WorkflowContext<A> ctx, A argument) {
            return execute((WorkflowContextImpl<A, R>) ctx, argument);
        }

    }

    private <A, R> void registerWorkflow(
            final String name,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final InternalWorkflow<A, R> executor) {
        engine.registerWorkflowInternal(name, 1, argumentConverter, resultConverter, WORKFLOW_TASK_QUEUE, Duration.ofSeconds(5), executor);
    }

    private void registerWorkflow(final String name, final InternalWorkflow<Void, Void> executor) {
        registerWorkflow(name, voidConverter(), voidConverter(), executor);
    }

    private <A, R> void registerActivity(
            final String name,
            final PayloadConverter<A> argumentConverter,
            final PayloadConverter<R> resultConverter,
            final Activity<A, R> executor) {
        engine.registerActivityInternal(name, argumentConverter, resultConverter, ACTIVITY_TASK_QUEUE, Duration.ofSeconds(5), executor);
    }

    private void registerActivity(final String name, final Activity<Void, Void> executor) {
        registerActivity(name, voidConverter(), voidConverter(), executor);
    }

    private void registerWorkflowWorker(final String name, final int maxConcurrency) {
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, name, WORKFLOW_TASK_QUEUE, maxConcurrency)
                        .withMinPollInterval(Duration.ofMillis(10))
                        .withPollBackoffFunction(IntervalFunction.of(10)));
    }

    private void registerTaskWorker(final String name, final int maxConcurrency) {
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, name, ACTIVITY_TASK_QUEUE, maxConcurrency)
                        .withMinPollInterval(Duration.ofMillis(10))
                        .withPollBackoffFunction(IntervalFunction.of(10)));
    }

    private WorkflowRunMetadata awaitRunStatus(
            final UUID runId,
            final WorkflowRunStatus expectedStatus,
            final Duration timeout) {
        return await("Workflow Run Status to become " + expectedStatus)
                .atMost(timeout)
                .failFast(() -> {
                    final WorkflowRunStatus currentStatus = engine.getRunMetadataById(runId).status();
                    if (currentStatus.isTerminal() && !expectedStatus.isTerminal()) {
                        return true;
                    }

                    return currentStatus.isTerminal()
                            && expectedStatus.isTerminal()
                            && currentStatus != expectedStatus;
                })
                .until(() -> engine.getRunMetadataById(runId), run -> run.status() == expectedStatus);
    }

    private WorkflowRunMetadata awaitRunStatus(final UUID runId, final WorkflowRunStatus expectedStatus) {
        return awaitRunStatus(runId, expectedStatus, Duration.ofSeconds(30));
    }

}