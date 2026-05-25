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

import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ListWorkflowRunsRequestTest {

    @Test
    void shouldPopulateFieldsUsingWithers() {
        final var request = new ListWorkflowRunsRequest()
                .withWorkflowName("workflowName")
                .withWorkflowVersion(123)
                .withStatuses(Set.of(WorkflowRunStatus.RUNNING, WorkflowRunStatus.CREATED))
                .withLabels(Map.of("foo", "bar"))
                .withCreatedSince(Instant.ofEpochSecond(111))
                .withCreatedBefore(Instant.ofEpochSecond(222))
                .withCompletedSince(Instant.ofEpochSecond(333))
                .withCompletedBefore(Instant.ofEpochSecond(444))
                .withPageToken("pageToken")
                .withLimit(666);

        assertThat(request.workflowName()).isEqualTo("workflowName");
        assertThat(request.workflowVersion()).isEqualTo(123);
        assertThat(request.statuses()).containsExactlyInAnyOrder(WorkflowRunStatus.RUNNING, WorkflowRunStatus.CREATED);
        assertThat(request.labels()).containsEntry("foo", "bar");
        assertThat(request.createdSince()).isEqualTo(Instant.ofEpochSecond(111));
        assertThat(request.createdBefore()).isEqualTo(Instant.ofEpochSecond(222));
        assertThat(request.completedSince()).isEqualTo(Instant.ofEpochSecond(333));
        assertThat(request.completedBefore()).isEqualTo(Instant.ofEpochSecond(444));
        assertThat(request.pageToken()).isEqualTo("pageToken");
        assertThat(request.limit()).isEqualTo(666);
    }

}