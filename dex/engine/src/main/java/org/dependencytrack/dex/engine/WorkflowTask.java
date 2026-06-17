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

import org.dependencytrack.dex.engine.persistence.model.PolledWorkflowTask;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public record WorkflowTask(
        UUID workflowRunId,
        String workflowName,
        int workflowVersion,
        String workflowInstanceId,
        String queueName,
        @Nullable String concurrencyKey,
        int priority,
        @Nullable Map<String, String> labels,
        int continuedAsNewGeneration,
        List<WorkflowEvent> history,
        List<WorkflowEvent> inbox,
        List<Long> inboxMessageIds,
        TaskLock lock) implements Task {

    static WorkflowTask of(
            final PolledWorkflowTask polledTask,
            final List<WorkflowEvent> history,
            final List<WorkflowEvent> inbox,
            final List<Long> inboxMessageIds) {
        return new WorkflowTask(
                polledTask.runId(),
                polledTask.workflowName(),
                polledTask.workflowVersion(),
                polledTask.workflowInstanceId(),
                polledTask.queueName(),
                polledTask.concurrencyKey(),
                polledTask.priority(),
                polledTask.labels(),
                polledTask.continuedAsNewGeneration(),
                history,
                inbox,
                inboxMessageIds,
                new TaskLock(
                        polledTask.lockedUntil(),
                        polledTask.lockVersion())
        );
    }

}
