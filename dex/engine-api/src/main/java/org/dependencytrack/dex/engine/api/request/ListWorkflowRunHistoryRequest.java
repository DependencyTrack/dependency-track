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
import org.jspecify.annotations.Nullable;

import java.util.UUID;

import static java.util.Objects.requireNonNull;

public record ListWorkflowRunHistoryRequest(
        UUID runId,
        @Nullable Integer fromSequenceNumber,
        @Nullable String pageToken,
        int limit,
        @Nullable SortDirection sortDirection) {

    public ListWorkflowRunHistoryRequest {
        requireNonNull(runId, "runId must not be null");
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be greater than 0");
        }
        if (pageToken != null && fromSequenceNumber != null) {
            throw new IllegalArgumentException("pageToken and fromSequenceNumber must not both be set");
        }
        if (fromSequenceNumber != null && fromSequenceNumber < 0) {
            throw new IllegalArgumentException("fromSequenceNumber must be greater than 0");
        }
    }

    public ListWorkflowRunHistoryRequest(UUID runId) {
        this(runId, null, null, 10, null);
    }

    public ListWorkflowRunHistoryRequest withFromSequenceNumber(@Nullable Integer fromSequenceNumber) {
        return new ListWorkflowRunHistoryRequest(this.runId, fromSequenceNumber, this.pageToken, this.limit, this.sortDirection);
    }

    public ListWorkflowRunHistoryRequest withPageToken(@Nullable String pageToken) {
        return new ListWorkflowRunHistoryRequest(this.runId, this.fromSequenceNumber, pageToken, this.limit, this.sortDirection);
    }

    public ListWorkflowRunHistoryRequest withLimit(int limit) {
        return new ListWorkflowRunHistoryRequest(this.runId, this.fromSequenceNumber, this.pageToken, limit, this.sortDirection);
    }

    public ListWorkflowRunHistoryRequest withSortDirection(@Nullable SortDirection sortDirection) {
        return new ListWorkflowRunHistoryRequest(this.runId, this.fromSequenceNumber, this.pageToken, this.limit, sortDirection);
    }

}
