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
package org.dependencytrack.dex.engine.api.request;

import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/**
 * Request for creating a workflow run.
 *
 * @param requestId       Unique identifier of the request.
 * @param workflowName    Name of the workflow. Must be known to the engine.
 * @param workflowVersion Version of the workflow. Must be between 1 and 100.
 * @param taskQueueName   Name of the queue to schedule tasks on.
 * @param concurrencyKey  Concurrency key for the run.
 * @param priority        Priority of the run. Must be between 0 and 100.
 * @param labels          Labels for the run.
 * @param argument        Argument for the run.
 * @param <A>             Type of the workflow argument.
 */
public record CreateWorkflowRunRequest<A>(
        UUID requestId,
        String workflowName,
        int workflowVersion,
        @Nullable String workflowInstanceId,
        @Nullable String taskQueueName,
        @Nullable String concurrencyKey,
        int priority,
        @Nullable Map<String, String> labels,
        @Nullable A argument) {

    public CreateWorkflowRunRequest {
        requireNonNull(requestId, "requestId must not be null");
        requireNonNull(workflowName, "workflowName must not be null");
        if (workflowVersion < 1 || workflowVersion > 100) {
            throw new IllegalArgumentException("workflowVersion must be between 1 and 100, but is " + workflowVersion);
        }
        if (priority < 0 || priority > 100) {
            throw new IllegalArgumentException("priority must be between 0 and 100, but is " + priority);
        }
    }

    public CreateWorkflowRunRequest(String workflowName, int workflowVersion) {
        this(UUID.randomUUID(), workflowName, workflowVersion, null, null, null, 0, null, null);
    }

    public CreateWorkflowRunRequest(Class<? extends Workflow<A, ?>> executorClass) {
        this(getWorkflowName(executorClass), getWorkflowVersion(executorClass));
    }

    public CreateWorkflowRunRequest<A> withWorkflowInstanceId(@Nullable String workflowInstanceId) {
        return new CreateWorkflowRunRequest<>(
                this.requestId,
                this.workflowName,
                this.workflowVersion,
                workflowInstanceId,
                this.taskQueueName,
                this.concurrencyKey,
                this.priority,
                this.labels,
                this.argument);
    }

    public CreateWorkflowRunRequest<A> withTaskQueueName(@Nullable String taskQueueName) {
        return new CreateWorkflowRunRequest<>(
                this.requestId,
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                taskQueueName,
                this.concurrencyKey,
                this.priority,
                this.labels,
                this.argument);
    }

    public CreateWorkflowRunRequest<A> withConcurrencyKey(@Nullable String concurrencyKey) {
        return new CreateWorkflowRunRequest<>(
                this.requestId,
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.taskQueueName,
                concurrencyKey,
                this.priority,
                this.labels,
                this.argument);
    }

    public CreateWorkflowRunRequest<A> withPriority(int priority) {
        return new CreateWorkflowRunRequest<>(
                this.requestId,
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.taskQueueName,
                this.concurrencyKey,
                priority,
                this.labels,
                this.argument);
    }

    public CreateWorkflowRunRequest<A> withLabels(@Nullable Map<String, String> labels) {
        return new CreateWorkflowRunRequest<>(
                this.requestId,
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.taskQueueName,
                this.concurrencyKey,
                this.priority,
                labels,
                this.argument);
    }

    public CreateWorkflowRunRequest<A> withArgument(@Nullable A argument) {
        return new CreateWorkflowRunRequest<>(
                this.requestId,
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.taskQueueName,
                this.concurrencyKey,
                this.priority,
                this.labels,
                argument);
    }

    private static String getWorkflowName(Class<? extends Workflow<?, ?>> executorClass) {
        final WorkflowSpec annotation = executorClass.getAnnotation(WorkflowSpec.class);
        if (annotation == null) {
            throw new IllegalArgumentException("Class %s is not annotated with @%s".formatted(
                    executorClass.getName(), WorkflowSpec.class.getName()));
        }

        return annotation.name();
    }

    private static int getWorkflowVersion(final Class<? extends Workflow<?, ?>> executorClass) {
        final WorkflowSpec annotation = executorClass.getAnnotation(WorkflowSpec.class);
        if (annotation == null) {
            throw new IllegalArgumentException("Class %s is not annotated with @%s".formatted(
                    executorClass.getName(), WorkflowSpec.class.getName()));
        }

        return annotation.version();
    }

}
