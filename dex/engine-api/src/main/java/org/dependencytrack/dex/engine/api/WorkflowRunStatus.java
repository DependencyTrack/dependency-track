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
package org.dependencytrack.dex.engine.api;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_CANCELLED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_CREATED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_FAILED;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_RUNNING;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_SUSPENDED;

public enum WorkflowRunStatus {

    CREATED(1, 3),       // 0
    RUNNING(2, 3, 4, 5), // 1
    SUSPENDED(1, 3),     // 2
    CANCELLED,           // 3
    COMPLETED,           // 4
    FAILED;              // 5

    public static final Set<WorkflowRunStatus> NON_TERMINAL_STATUSES =
            Arrays.stream(values())
                    .filter(status -> !status.isTerminal())
                    .collect(Collectors.toUnmodifiableSet());

    private final Set<Integer> allowedTransitions;

    WorkflowRunStatus(Integer... allowedTransitions) {
        this.allowedTransitions = Set.of(allowedTransitions);
    }

    public boolean canTransitionTo(WorkflowRunStatus newState) {
        return allowedTransitions.contains(newState.ordinal());
    }

    public boolean isTerminal() {
        return !equals(CREATED) && !equals(RUNNING) && !equals(SUSPENDED);
    }

    public static WorkflowRunStatus fromProto(
            org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus protoStatus) {
        return switch (protoStatus) {
            case WORKFLOW_RUN_STATUS_CREATED -> CREATED;
            case WORKFLOW_RUN_STATUS_RUNNING -> RUNNING;
            case WORKFLOW_RUN_STATUS_SUSPENDED -> SUSPENDED;
            case WORKFLOW_RUN_STATUS_CANCELLED -> CANCELLED;
            case WORKFLOW_RUN_STATUS_COMPLETED -> COMPLETED;
            case WORKFLOW_RUN_STATUS_FAILED -> FAILED;
            default -> throw new IllegalArgumentException("Unexpected status: " + protoStatus);
        };
    }

    public org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus toProto() {
        return switch (this) {
            case CREATED -> WORKFLOW_RUN_STATUS_CREATED;
            case RUNNING -> WORKFLOW_RUN_STATUS_RUNNING;
            case SUSPENDED -> WORKFLOW_RUN_STATUS_SUSPENDED;
            case CANCELLED -> WORKFLOW_RUN_STATUS_CANCELLED;
            case COMPLETED -> WORKFLOW_RUN_STATUS_COMPLETED;
            case FAILED -> WORKFLOW_RUN_STATUS_FAILED;
        };
    }

}
