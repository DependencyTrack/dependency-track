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
package org.dependencytrack.resources.v2;

import com.google.protobuf.util.Timestamps;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.dex.api.payload.PayloadConverters;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunHistoryEntry;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.proto.event.v1.RunCompleted;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.proto.common.v1.WorkflowRunStatus.WORKFLOW_RUN_STATUS_COMPLETED;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class WorkflowsResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig()
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(DEX_ENGINE_MOCK).to(DexEngine.class);
                        }
                    }));

    @AfterEach
    void afterEach() {
        Mockito.reset(DEX_ENGINE_MOCK);
    }

    @Test
    void getWorkflowInstanceShouldReturnMetadataOfWorkflowRun() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var workflowRunMetadata = new WorkflowRunMetadata(
                UUID.fromString("724c0700-4eeb-45f0-8ff4-8bba369c0174"),
                null,
                "workflowName",
                66,
                "workflowInstanceId",
                "taskQueueName",
                WorkflowRunStatus.RUNNING,
                "customStatus",
                12,
                "concurrencyKey",
                Map.of("foo", "bar"),
                Instant.ofEpochMilli(666666),
                Instant.ofEpochMilli(777777),
                Instant.ofEpochMilli(888888),
                null);

        doReturn(workflowRunMetadata)
                .when(DEX_ENGINE_MOCK).getRunMetadataByInstanceId(eq("foo"));

        final Response response = jersey
                .target("/internal/workflow-instances/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "id": "724c0700-4eeb-45f0-8ff4-8bba369c0174",
                  "workflow_name": "workflowName",
                  "workflow_version": 66,
                  "workflow_instance_id": "workflowInstanceId",
                  "task_queue_name": "taskQueueName",
                  "status": "RUNNING",
                  "created_at": 666666,
                  "priority": 12,
                  "concurrency_key": "concurrencyKey",
                  "labels": {
                    "foo": "bar"
                  },
                  "updated_at": 777777,
                  "started_at": 888888
                }
                """);
    }

    @Test
    void getWorkflowInstanceShouldReturnNotFoundWhenNoMatchingRunExists() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        doReturn(null)
                .when(DEX_ENGINE_MOCK).getRunMetadataByInstanceId(eq("foo"));

        final Response response = jersey
                .target("/internal/workflow-instances/foo")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type":"about:blank",
                  "status": 404,
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    void getWorkflowRunShouldReturnMetadataOfWorkflowRun() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var runId = UUID.fromString("724c0700-4eeb-45f0-8ff4-8bba369c0174");
        final var workflowRunMetadata = new WorkflowRunMetadata(
                runId,
                null,
                "workflowName",
                66,
                "workflowInstanceId",
                "taskQueueName",
                WorkflowRunStatus.RUNNING,
                "customStatus",
                12,
                "concurrencyKey",
                Map.of("foo", "bar"),
                Instant.ofEpochMilli(666666),
                Instant.ofEpochMilli(777777),
                Instant.ofEpochMilli(888888),
                null);

        doReturn(workflowRunMetadata)
                .when(DEX_ENGINE_MOCK).getRunMetadataById(eq(runId));

        final Response response = jersey
                .target("/internal/workflow-runs/%s".formatted(runId))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "id": "724c0700-4eeb-45f0-8ff4-8bba369c0174",
                  "workflow_name": "workflowName",
                  "workflow_version": 66,
                  "workflow_instance_id": "workflowInstanceId",
                  "task_queue_name": "taskQueueName",
                  "status": "RUNNING",
                  "created_at": 666666,
                  "priority": 12,
                  "concurrency_key": "concurrencyKey",
                  "labels": {
                    "foo": "bar"
                  },
                  "updated_at": 777777,
                  "started_at": 888888
                }
                """);
    }

    @Test
    void getWorkflowRunShouldReturnNotFoundWhenNoMatchingRunExists() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var runId = UUID.fromString("724c0700-4eeb-45f0-8ff4-8bba369c0174");

        doReturn(null)
                .when(DEX_ENGINE_MOCK).getRunMetadataById(eq(runId));

        final Response response = jersey
                .target("/internal/workflow-runs/%s".formatted(runId))
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type":"about:blank",
                  "status": 404,
                  "title": "Not Found",
                  "detail": "The requested resource could not be found."
                }
                """);
    }

    @Test
    public void listWorkflowRunsShouldReturnWorkflowRunMetadata() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var workflowRunMetadata = new WorkflowRunMetadata(
                UUID.fromString("724c0700-4eeb-45f0-8ff4-8bba369c0174"),
                null,
                "workflowName",
                66,
                "workflowInstanceId",
                "taskQueueName",
                WorkflowRunStatus.RUNNING,
                "customStatus",
                12,
                "concurrencyKey",
                Map.of("foo", "bar"),
                Instant.ofEpochMilli(666666),
                Instant.ofEpochMilli(777777),
                Instant.ofEpochMilli(888888),
                null);

        doReturn(new Page<>(List.of(workflowRunMetadata), null).withTotalCount(1, TotalCount.Type.EXACT))
                .when(DEX_ENGINE_MOCK).listRuns(any(ListWorkflowRunsRequest.class));

        final Response response = jersey
                .target("/internal/workflow-runs")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "items": [
                            {
                              "id": "724c0700-4eeb-45f0-8ff4-8bba369c0174",
                              "workflow_name": "workflowName",
                              "workflow_version": 66,
                              "workflow_instance_id": "workflowInstanceId",
                              "task_queue_name": "taskQueueName",
                              "status": "RUNNING",
                              "created_at": 666666,
                              "priority": 12,
                              "concurrency_key": "concurrencyKey",
                              "labels": {
                                "foo": "bar"
                              },
                              "updated_at": 777777,
                              "started_at": 888888
                            }
                          ],
                          "total": {
                            "count": 1,
                            "type": "EXACT"
                          }
                        }
                        """);
    }

    @Test
    public void listWorkflowRunsShouldPassQueryParametersToDexEngine() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        doReturn(Page.empty())
                .when(DEX_ENGINE_MOCK).listRuns(any(ListWorkflowRunsRequest.class));

        final Response response = jersey
                .target("/internal/workflow-runs")
                .queryParam("workflow_name", "testWorkflow")
                .queryParam("workflow_version", 42)
                .queryParam("workflow_instance_id", "instance-123")
                .queryParam("status", "CANCELLED")
                .queryParam("label", "env=prod", "team=api")
                .queryParam("created_since", 1000000)
                .queryParam("created_before", 2000000)
                .queryParam("completed_since", 3000000)
                .queryParam("completed_before", 4000000)
                .queryParam("limit", 50)
                .queryParam("page_token", "nextPageToken")
                .queryParam("sort_direction", "DESC")
                .queryParam("sort_by", "created_at")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);

        final var requestCaptor = ArgumentCaptor.forClass(ListWorkflowRunsRequest.class);
        verify(DEX_ENGINE_MOCK).listRuns(requestCaptor.capture());

        final ListWorkflowRunsRequest capturedRequest = requestCaptor.getValue();
        assertThat(capturedRequest.workflowName()).isEqualTo("testWorkflow");
        assertThat(capturedRequest.workflowVersion()).isEqualTo(42);
        assertThat(capturedRequest.workflowInstanceId()).isEqualTo("instance-123");
        assertThat(capturedRequest.statuses()).containsOnly(WorkflowRunStatus.CANCELLED);
        assertThat(capturedRequest.labels()).containsExactlyInAnyOrderEntriesOf(Map.of("env", "prod", "team", "api"));
        assertThat(capturedRequest.createdSince()).isEqualTo(Instant.ofEpochMilli(1000000));
        assertThat(capturedRequest.createdBefore()).isEqualTo(Instant.ofEpochMilli(2000000));
        assertThat(capturedRequest.completedSince()).isEqualTo(Instant.ofEpochMilli(3000000));
        assertThat(capturedRequest.completedBefore()).isEqualTo(Instant.ofEpochMilli(4000000));
        assertThat(capturedRequest.limit()).isEqualTo(50);
        assertThat(capturedRequest.pageToken()).isEqualTo("nextPageToken");
        assertThat(capturedRequest.sortDirection()).isEqualTo(SortDirection.DESC);
        assertThat(capturedRequest.sortBy()).isEqualTo(ListWorkflowRunsRequest.SortBy.CREATED_AT);
    }

    @Test
    public void listWorkflowRunsShouldReturn400WhenLabelFilterIsMalformed() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response missingEquals = jersey
                .target("/internal/workflow-runs")
                .queryParam("label", "noEqualsSign")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(missingEquals.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(missingEquals)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "The request could not be processed because it failed validation.",
                  "errors": [
                    {
                      "path": "listWorkflowRuns.label[0].<list element>",
                      "value": "noEqualsSign",
                      "message": "must match \\"^[^=]+=.*$\\""
                    }
                  ]
                }
                """);

        final Response emptyKey = jersey
                .target("/internal/workflow-runs")
                .queryParam("label", "=value")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(emptyKey.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(emptyKey)).isEqualTo(/* language=JSON */ """
                {
                  "type": "about:blank",
                  "status": 400,
                  "title": "Bad Request",
                  "detail": "The request could not be processed because it failed validation.",
                  "errors": [
                    {
                      "path": "listWorkflowRuns.label[0].<list element>",
                      "value": "=value",
                      "message": "must match \\"^[^=]+=.*$\\""
                    }
                  ]
                }
                """);
    }

    @Test
    public void shouldReturn400WhenSortByFieldIsNotSupportedForListWorkflowRuns() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final Response response = jersey
                .target("/internal/workflow-runs")
                .queryParam("sort_by", "invalid_field")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "type": "/problems/invalid-sort-field",
                  "status": 400,
                  "title": "Invalid sort field",
                  "detail": "Sorting by field 'invalid_field' is not supported",
                  "invalid_field": "invalid_field",
                  "supported_fields": ["id", "created_at", "completed_at"]
                }
                """);
    }

    @Test
    public void listWorkflowRunHistoryShouldReturnWorkflowRunHistory() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var event = WorkflowEvent.newBuilder()
                .setId(-1)
                .setTimestamp(Timestamps.fromSeconds(666666))
                .setRunCompleted(RunCompleted.newBuilder()
                        .setStatus(WORKFLOW_RUN_STATUS_COMPLETED)
                        .setCustomStatus("customStatus")
                        .setResult(PayloadConverters.stringConverter().convertToPayload("payload"))
                        .build())
                .build();

        doReturn(new Page<>(List.of(new WorkflowRunHistoryEntry(0, event)), null).withTotalCount(1, TotalCount.Type.EXACT))
                .when(DEX_ENGINE_MOCK).listRunHistory(any(ListWorkflowRunHistoryRequest.class));

        final Response response = jersey
                .target("/internal/workflow-runs/de10c1ec-959e-486d-a031-deb97963ff7c/events")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "items": [
                            {
                              "sequence_number": 0,
                              "event": {
                                "id": -1,
                                "timestamp": "1970-01-08T17:11:06Z",
                                "runCompleted": {
                                  "status": "WORKFLOW_RUN_STATUS_COMPLETED",
                                  "customStatus": "customStatus",
                                  "result": {
                                    "binaryContent": {
                                      "mediaType": "text/plain",
                                      "data": "cGF5bG9hZA=="
                                    }
                                  }
                                }
                              }
                            }
                          ],
                          "total": {
                            "count": 1,
                            "type": "EXACT"
                          }
                        }
                        """);
    }

    @Test
    void listWorkflowRunEventsShouldPassQueryParametersToDexEngine() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        doReturn(Page.empty())
                .when(DEX_ENGINE_MOCK).listRunHistory(any(ListWorkflowRunHistoryRequest.class));

        final Response response = jersey
                .target("/internal/workflow-runs/de10c1ec-959e-486d-a031-deb97963ff7c/events")
                .queryParam("from_sequence_number", 42)
                .queryParam("limit", 25)
                .queryParam("sort_direction", "DESC")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);

        final var requestCaptor = ArgumentCaptor.forClass(ListWorkflowRunHistoryRequest.class);
        verify(DEX_ENGINE_MOCK).listRunHistory(requestCaptor.capture());

        final ListWorkflowRunHistoryRequest capturedRequest = requestCaptor.getValue();
        assertThat(capturedRequest.runId()).isEqualTo(UUID.fromString("de10c1ec-959e-486d-a031-deb97963ff7c"));
        assertThat(capturedRequest.fromSequenceNumber()).isEqualTo(42);
        assertThat(capturedRequest.limit()).isEqualTo(25);
        assertThat(capturedRequest.sortDirection()).isEqualTo(SortDirection.DESC);
        assertThat(capturedRequest.pageToken()).isNull();
    }

}