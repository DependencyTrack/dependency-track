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

import alpine.server.auth.PermissionRequired;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.TaskQueuesApi;
import org.dependencytrack.api.v2.model.ListTaskQueuesResponse;
import org.dependencytrack.api.v2.model.TaskQueue;
import org.dependencytrack.api.v2.model.TaskQueueStatus;
import org.dependencytrack.api.v2.model.TaskQueueType;
import org.dependencytrack.api.v2.model.UpdateTaskQueueRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.request.ListTaskQueuesRequest;
import org.dependencytrack.resources.AbstractApiResource;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
@NullMarked
public final class TaskQueuesResource extends AbstractApiResource implements TaskQueuesApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(TaskQueuesResource.class);

    private final DexEngine dexEngine;

    @Inject
    TaskQueuesResource(DexEngine dexEngine) {
        this.dexEngine = dexEngine;
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listTaskQueues(TaskQueueType type, Integer limit, @Nullable String pageToken) {
        final Page<org.dependencytrack.dex.engine.api.TaskQueue> taskQueuesPage =
                dexEngine.listTaskQueues(new ListTaskQueuesRequest(convert(type))
                        .withPageToken(pageToken)
                        .withLimit(limit));

        final var response = ListTaskQueuesResponse.builder()
                .items(taskQueuesPage.items().stream()
                        .map(TaskQueuesResource::convert)
                        .toList())
                .nextPageToken(taskQueuesPage.nextPageToken())
                .total(convertTotalCount(taskQueuesPage.totalCount()))
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateTaskQueue(TaskQueueType type, String name, UpdateTaskQueueRequest request) {
        final boolean updated = dexEngine.updateTaskQueue(
                new org.dependencytrack.dex.engine.api.request.UpdateTaskQueueRequest(
                        convert(type),
                        name,
                        convert(request.getStatus()),
                        request.getCapacity()));
        if (updated) {
            LOGGER.info(
                    SecurityMarkers.SECURITY_AUDIT,
                    "Updated {} task queue '{}'",
                    type.name().toLowerCase(),
                    name);
        } else {
            LOGGER.info(
                    SecurityMarkers.SECURITY_AUDIT,
                    "Update of {} task queue '{}' requested, but it has not changed",
                    type.name().toLowerCase(),
                    name);
        }

        return Response.noContent().build();
    }

    private static TaskType convert(TaskQueueType type) {
        return switch (type) {
            case ACTIVITY -> TaskType.ACTIVITY;
            case WORKFLOW -> TaskType.WORKFLOW;
        };
    }

    private static org.dependencytrack.dex.engine.api.@Nullable TaskQueueStatus convert(@Nullable TaskQueueStatus status) {
        return switch (status) {
            case ACTIVE -> org.dependencytrack.dex.engine.api.TaskQueueStatus.ACTIVE;
            case PAUSED -> org.dependencytrack.dex.engine.api.TaskQueueStatus.PAUSED;
            case null -> null;
        };
    }

    private static TaskQueue convert(org.dependencytrack.dex.engine.api.TaskQueue queue) {
        return TaskQueue.builder()
                .name(queue.name())
                .status(switch (queue.status()) {
                    case ACTIVE -> TaskQueueStatus.ACTIVE;
                    case PAUSED -> TaskQueueStatus.PAUSED;
                })
                .capacity(queue.capacity())
                .depth(queue.depth())
                .createdAt(queue.createdAt().toEpochMilli())
                .updatedAt(queue.updatedAt() != null
                        ? queue.updatedAt().toEpochMilli()
                        : null)
                .build();
    }

}
