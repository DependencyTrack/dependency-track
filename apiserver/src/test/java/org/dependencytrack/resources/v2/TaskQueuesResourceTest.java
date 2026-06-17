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

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.Page.TotalCount;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskQueue;
import org.dependencytrack.dex.engine.api.TaskQueueStatus;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.request.ListTaskQueuesRequest;
import org.dependencytrack.dex.engine.api.request.UpdateTaskQueueRequest;
import org.glassfish.jersey.inject.hk2.AbstractBinder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class TaskQueuesResourceTest extends ResourceTest {

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
    void shouldListActivityTaskQueues() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var queue = new TaskQueue(
                TaskType.ACTIVITY,
                "test-queue",
                TaskQueueStatus.ACTIVE,
                10,
                3,
                Instant.ofEpochMilli(1000000),
                Instant.ofEpochMilli(2000000));

        doReturn(new Page<>(List.of(queue), null).withTotalCount(1, TotalCount.Type.EXACT))
                .when(DEX_ENGINE_MOCK).listTaskQueues(any(ListTaskQueuesRequest.class));

        final Response response = jersey
                .target("/internal/task-queues/ACTIVITY")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "name": "test-queue",
                      "status": "ACTIVE",
                      "capacity": 10,
                      "depth": 3,
                      "created_at": 1000000,
                      "updated_at": 2000000
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
    void shouldListWorkflowTaskQueues() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        final var queue = new TaskQueue(
                TaskType.WORKFLOW,
                "wf-queue",
                TaskQueueStatus.PAUSED,
                5,
                0,
                Instant.ofEpochMilli(3000000),
                null);

        doReturn(new Page<>(List.of(queue), null).withTotalCount(1, TotalCount.Type.EXACT))
                .when(DEX_ENGINE_MOCK).listTaskQueues(any(ListTaskQueuesRequest.class));

        final Response response = jersey
                .target("/internal/task-queues/WORKFLOW")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "items": [
                    {
                      "name": "wf-queue",
                      "status": "PAUSED",
                      "capacity": 5,
                      "depth": 0,
                      "created_at": 3000000
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
    void shouldPassPaginationParametersWhenListingTaskQueues() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_READ);

        doReturn(Page.empty())
                .when(DEX_ENGINE_MOCK).listTaskQueues(any(ListTaskQueuesRequest.class));

        final Response response = jersey
                .target("/internal/task-queues/ACTIVITY")
                .queryParam("limit", 25)
                .queryParam("page_token", "nextToken")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);

        final var requestCaptor = ArgumentCaptor.forClass(ListTaskQueuesRequest.class);
        verify(DEX_ENGINE_MOCK).listTaskQueues(requestCaptor.capture());

        final ListTaskQueuesRequest capturedRequest = requestCaptor.getValue();
        assertThat(capturedRequest.type()).isEqualTo(TaskType.ACTIVITY);
        assertThat(capturedRequest.limit()).isEqualTo(25);
        assertThat(capturedRequest.pageToken()).isEqualTo("nextToken");
    }

    @Test
    void shouldUpdateTaskQueueStatus() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        doReturn(true)
                .when(DEX_ENGINE_MOCK).updateTaskQueue(any(UpdateTaskQueueRequest.class));

        final Response response = jersey
                .target("/internal/task-queues/ACTIVITY/test-queue")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "status": "PAUSED"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);

        final var requestCaptor = ArgumentCaptor.forClass(UpdateTaskQueueRequest.class);
        verify(DEX_ENGINE_MOCK).updateTaskQueue(requestCaptor.capture());

        final UpdateTaskQueueRequest capturedRequest = requestCaptor.getValue();
        assertThat(capturedRequest.type()).isEqualTo(TaskType.ACTIVITY);
        assertThat(capturedRequest.name()).isEqualTo("test-queue");
        assertThat(capturedRequest.status()).isEqualTo(TaskQueueStatus.PAUSED);
        assertThat(capturedRequest.capacity()).isNull();
    }

    @Test
    void shouldUpdateTaskQueueCapacity() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        doReturn(true)
                .when(DEX_ENGINE_MOCK).updateTaskQueue(any(UpdateTaskQueueRequest.class));

        final Response response = jersey
                .target("/internal/task-queues/WORKFLOW/wf-queue")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "capacity": 20
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(204);

        final var requestCaptor = ArgumentCaptor.forClass(UpdateTaskQueueRequest.class);
        verify(DEX_ENGINE_MOCK).updateTaskQueue(requestCaptor.capture());

        final UpdateTaskQueueRequest capturedRequest = requestCaptor.getValue();
        assertThat(capturedRequest.type()).isEqualTo(TaskType.WORKFLOW);
        assertThat(capturedRequest.name()).isEqualTo("wf-queue");
        assertThat(capturedRequest.status()).isNull();
        assertThat(capturedRequest.capacity()).isEqualTo(20);
    }

    @Test
    void shouldReturnNotFoundWhenUpdatingNonExistentQueue() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        doThrow(new NoSuchElementException("Queue does not exist"))
                .when(DEX_ENGINE_MOCK).updateTaskQueue(any(UpdateTaskQueueRequest.class));

        final Response response = jersey
                .target("/internal/task-queues/ACTIVITY/nonexistent")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {
                          "status": "ACTIVE"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void shouldReturnNoContentWhenNoFieldsProvided() {
        initializeWithPermissions(Permissions.SYSTEM_CONFIGURATION_UPDATE);

        doReturn(false)
                .when(DEX_ENGINE_MOCK).updateTaskQueue(any(UpdateTaskQueueRequest.class));

        final Response response = jersey
                .target("/internal/task-queues/ACTIVITY/test-queue")
                .request()
                .header(X_API_KEY, apiKey)
                .method("PATCH", Entity.json(/* language=JSON */ """
                        {}
                        """));
        assertThat(response.getStatus()).isEqualTo(204);

        final var requestCaptor = ArgumentCaptor.forClass(UpdateTaskQueueRequest.class);
        verify(DEX_ENGINE_MOCK).updateTaskQueue(requestCaptor.capture());

        final UpdateTaskQueueRequest capturedRequest = requestCaptor.getValue();
        assertThat(capturedRequest.type()).isEqualTo(TaskType.ACTIVITY);
        assertThat(capturedRequest.name()).isEqualTo("test-queue");
        assertThat(capturedRequest.status()).isNull();
        assertThat(capturedRequest.capacity()).isNull();
    }

}
