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

import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

public record ListWorkflowRunsRequest(
        @Nullable String workflowName,
        @Nullable Integer workflowVersion,
        @Nullable String workflowInstanceId,
        @Nullable Set<WorkflowRunStatus> statuses,
        @Nullable Map<String, String> labels,
        @Nullable Instant createdSince,
        @Nullable Instant createdBefore,
        @Nullable Instant completedSince,
        @Nullable Instant completedBefore,
        @Nullable SortBy sortBy,
        @Nullable SortDirection sortDirection,
        @Nullable String pageToken,
        int limit) {

    public enum SortBy {
        ID,
        CREATED_AT,
        COMPLETED_AT
    }

    public ListWorkflowRunsRequest() {
        this(null, null, null, null, null, null, null, null, null, null, null, null, 10);
    }

    public ListWorkflowRunsRequest withWorkflowName(@Nullable String workflowName) {
        return new ListWorkflowRunsRequest(
                workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withWorkflowVersion(@Nullable Integer workflowVersion) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withWorkflowInstanceId(@Nullable String workflowInstanceId) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withStatuses(@Nullable Set<WorkflowRunStatus> statuses) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withLabels(@Nullable Map<String, String> labelFilter) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                labelFilter,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withCreatedSince(@Nullable Instant createdSince) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withCreatedBefore(@Nullable Instant createdBefore) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withCompletedSince(@Nullable Instant completedSince) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withCompletedBefore(@Nullable Instant completedBefore) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withPageToken(@Nullable String pageToken) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withLimit(int limit) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                this.sortDirection,
                this.pageToken,
                limit);
    }

    public ListWorkflowRunsRequest withSortBy(@Nullable SortBy sortBy) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                sortBy,
                this.sortDirection,
                this.pageToken,
                this.limit);
    }

    public ListWorkflowRunsRequest withSortDirection(@Nullable SortDirection sortDirection) {
        return new ListWorkflowRunsRequest(
                this.workflowName,
                this.workflowVersion,
                this.workflowInstanceId,
                this.statuses,
                this.labels,
                this.createdSince,
                this.createdBefore,
                this.completedSince,
                this.completedBefore,
                this.sortBy,
                sortDirection,
                this.pageToken,
                this.limit);
    }

}
