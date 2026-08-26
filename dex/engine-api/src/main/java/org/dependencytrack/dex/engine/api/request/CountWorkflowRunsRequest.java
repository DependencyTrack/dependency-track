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
import org.dependencytrack.dex.api.WorkflowSpecs;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.Set;

/// @param workflowName Name of the workflow to match.
/// @param statuses     Statuses to match.
/// @param labels       Labels to match. A run matches when it carries all of them.
/// @param limit        Maximum number of runs to count.
/// @since 5.1.0
public record CountWorkflowRunsRequest(
        @Nullable String workflowName,
        @Nullable Set<WorkflowRunStatus> statuses,
        @Nullable Map<String, String> labels,
        int limit) {

    public CountWorkflowRunsRequest {
        if ((workflowName == null || workflowName.isEmpty())
                && (statuses == null || statuses.isEmpty())
                && (labels == null || labels.isEmpty())) {
            throw new IllegalArgumentException("At least one filter must be provided");
        }
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be greater than zero");
        }
    }

    public CountWorkflowRunsRequest(
            @Nullable String workflowName, @Nullable Set<WorkflowRunStatus> statuses, int limit) {
        this(workflowName, statuses, null, limit);
    }

    public CountWorkflowRunsRequest(
            Class<? extends Workflow<?, ?>> workflowClass,
            @Nullable Set<WorkflowRunStatus> statuses,
            @Nullable Map<String, String> labels,
            int limit) {
        final WorkflowSpec spec = WorkflowSpecs.of(workflowClass);
        this(spec.name(), statuses, labels, limit);
    }
}
