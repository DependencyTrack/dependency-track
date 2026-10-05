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
package org.dependencytrack.policy;

import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.metrics.UpdateProjectMetricsActivity;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.assertArg;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class EvalProjectPoliciesWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private EvalProjectPoliciesActivity evalProjectPoliciesActivityMock;
    private UpdateProjectMetricsActivity updateProjectMetricsActivityMock;

    @BeforeEach
    void beforeEach() {
        evalProjectPoliciesActivityMock = mock(EvalProjectPoliciesActivity.class);
        updateProjectMetricsActivityMock = mock(UpdateProjectMetricsActivity.class);

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new EvalProjectPoliciesWorkflow(),
                protoConverter(EvalProjectPoliciesArg.class),
                voidConverter(),
                Duration.ofSeconds(10));
        engine.registerActivity(
                evalProjectPoliciesActivityMock, protoConverter(EvalProjectPoliciesArg.class), voidConverter());
        engine.registerActivity(
                updateProjectMetricsActivityMock, protoConverter(UpdateProjectMetricsArg.class), voidConverter());

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "policy-evaluations", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "metrics-updates", 1));

        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-policy-evaluations", "policy-evaluations", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-metrics-updates", "metrics-updates", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @Test
    void shouldEvaluatePoliciesThenUpdateMetrics() throws Exception {
        final var projectUuid = UUID.randomUUID();

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(EvalProjectPoliciesWorkflow.class)
                        .withArgument(EvalProjectPoliciesArg.newBuilder()
                                .setProjectUuid(projectUuid.toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final var order = inOrder(evalProjectPoliciesActivityMock, updateProjectMetricsActivityMock);
        order.verify(evalProjectPoliciesActivityMock)
                .execute(
                        any(ActivityContext.class),
                        assertArg(arg -> assertThat(arg.getProjectUuid()).isEqualTo(projectUuid.toString())));
        order.verify(updateProjectMetricsActivityMock)
                .execute(
                        any(ActivityContext.class),
                        assertArg(arg -> assertThat(arg.getProjectUuid()).isEqualTo(projectUuid.toString())));
    }

    @Test
    void shouldFailWhenArgumentIsNull() {
        final UUID runId =
                workflowTest.getEngine().createRun(new CreateWorkflowRunRequest<>(EvalProjectPoliciesWorkflow.class));

        final var run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).contains("No project UUID provided");
    }

    @Test
    void shouldFailWhenProjectUuidIsBlank() {
        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(EvalProjectPoliciesWorkflow.class)
                        .withArgument(EvalProjectPoliciesArg.getDefaultInstance()));

        final var run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run.failure()).isNotNull();
        assertThat(run.failure().getMessage()).contains("No project UUID provided");
    }

    @Test
    void shouldSkipMetricsUpdateWhenPolicyEvaluationFails() throws Exception {
        doThrow(new TerminalApplicationFailureException("policy evaluation failed"))
                .when(evalProjectPoliciesActivityMock)
                .execute(any(), any());

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(EvalProjectPoliciesWorkflow.class)
                        .withArgument(EvalProjectPoliciesArg.newBuilder()
                                .setProjectUuid(UUID.randomUUID().toString())
                                .build()));

        final var run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);
        assertThat(run.failure()).isNotNull();

        verify(updateProjectMetricsActivityMock, never()).execute(any(), any());
    }
}
