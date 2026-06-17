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
package org.dependencytrack.dex.api;

import org.jspecify.annotations.Nullable;

/**
 * @param taskQueueName  Name of the queue to schedule the workflow task on.
 * @param argument       Argument of the call.
 * @param concurrencyKey Concurrency key of the workflow run.
 * @param <A>
 */
public record WorkflowCallOptions<A extends @Nullable Object>(
        @Nullable String workflowInstanceId,
        @Nullable String taskQueueName,
        @Nullable A argument,
        @Nullable String concurrencyKey) {

    public WorkflowCallOptions() {
        this(null, null, null, null);
    }

    public WorkflowCallOptions<A> withWorkflowInstanceId(@Nullable String workflowInstanceId) {
        return new WorkflowCallOptions<>(workflowInstanceId, this.taskQueueName, this.argument, this.concurrencyKey);
    }

    public WorkflowCallOptions<A> withTaskQueueName(@Nullable String taskQueueName) {
        return new WorkflowCallOptions<>(this.workflowInstanceId, taskQueueName, this.argument, this.concurrencyKey);
    }

    public WorkflowCallOptions<A> withArgument(@Nullable A argument) {
        return new WorkflowCallOptions<>(this.workflowInstanceId, this.taskQueueName, argument, this.concurrencyKey);
    }

    public WorkflowCallOptions<A> withConcurrencyKey(@Nullable String concurrencyKey) {
        return new WorkflowCallOptions<>(this.workflowInstanceId, this.taskQueueName, this.argument, concurrencyKey);
    }

}
