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
package org.dependencytrack.dex.testing;

import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.stringConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

@Testcontainers
public class WorkflowTestRuleTest {

    @Container
    private static final PostgreSQLContainer POSTGRES_CONTAINER =
            new PostgreSQLContainer(DockerImageName.parse("postgres:14-alpine"));

    @RegisterExtension
    WorkflowTestExtension workflowTest = new WorkflowTestExtension(POSTGRES_CONTAINER);

    @Test
    public void shouldExecuteWorkflow() {
        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new TestWorkflow(),
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));
        engine.registerActivity(
                new TestActivity(),
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 10));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 10));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>(TestWorkflow.class));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.result()).isNotNull();
        assertThat(stringConverter().convertFromPayload(run.result())).isEqualTo("foo-bar");
    }

    @Test
    public void shouldSupportMockedActivities() {
        final var activityMock = mock(TestActivity.class);
        doReturn("mocked").when(activityMock).execute(any(ActivityContext.class), isNull());

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new TestWorkflow(),
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));
        engine.registerActivity(
                activityMock,
                voidConverter(),
                stringConverter(),
                Duration.ofSeconds(3));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 10));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 10));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();

        final UUID runId = engine.createRun(new CreateWorkflowRunRequest<>(TestWorkflow.class));

        final WorkflowRun run = workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        assertThat(run).isNotNull();
        assertThat(run.result()).isNotNull();
        assertThat(stringConverter().convertFromPayload(run.result())).isEqualTo("foo-mocked");
    }

    @WorkflowSpec(name = "test")
    public static class TestWorkflow implements Workflow<Void, String> {

        @Override
        public String execute(final WorkflowContext<Void> ctx, final @Nullable Void argument) {
            final String activityResult = ctx.activity(TestActivity.class).call().await();
            return "foo-" + activityResult;
        }

    }

    @ActivitySpec(name = "test")
    public static class TestActivity implements Activity<Void, String> {

        @Override
        public String execute(final ActivityContext ctx, final @Nullable Void argument) {
            return "bar";
        }

    }

}