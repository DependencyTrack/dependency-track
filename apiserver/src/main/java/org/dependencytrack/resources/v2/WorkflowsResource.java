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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.protobuf.util.JsonFormat;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.dependencytrack.api.v2.WorkflowsApi;
import org.dependencytrack.api.v2.model.ListWorkflowRunEventsResponse;
import org.dependencytrack.api.v2.model.ListWorkflowRunEventsResponseItem;
import org.dependencytrack.api.v2.model.ListWorkflowRunsResponse;
import org.dependencytrack.api.v2.model.SortDirection;
import org.dependencytrack.api.v2.model.WorkflowRunStatus;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunHistoryEntry;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunHistoryRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskCompleted;
import org.dependencytrack.dex.proto.event.v1.ActivityTaskFailed;
import org.dependencytrack.dex.proto.event.v1.ChildRunCompleted;
import org.dependencytrack.dex.proto.event.v1.ChildRunFailed;
import org.dependencytrack.dex.proto.event.v1.TimerElapsed;
import org.dependencytrack.dex.proto.event.v1.WorkflowEvent;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentArtifact;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentCommon;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentMetrics;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentNotification;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentPackageMetadata;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentVulnDataSource;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentVulnPolicy;
import org.dependencytrack.proto.internal.workflow.v1.ArgumentVulnanalysis;
import org.dependencytrack.proto.internal.workflow.v1.ResultVulnanalysis;
import org.dependencytrack.resources.AbstractApiResource;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.dependencytrack.resources.v2.mapping.ModelMapper.mapSortDirection;

@Provider
@NullMarked
public class WorkflowsResource extends AbstractApiResource implements WorkflowsApi {

    private final DexEngine dexEngine;
    private final ObjectMapper objectMapper;
    private final JsonFormat.Printer eventJsonPrinter;

    @Inject
    WorkflowsResource(DexEngine dexEngine, ObjectMapper objectMapper) {
        this.dexEngine = dexEngine;
        this.objectMapper = objectMapper;
        this.eventJsonPrinter = JsonFormat.printer()
                // Ensure that event IDs with value 0 are not omitted.
                .includingDefaultValueFields(Set.of(
                        WorkflowEvent.getDescriptor().findFieldByName("id"),
                        ActivityTaskCompleted.getDescriptor().findFieldByName("activity_task_created_event_id"),
                        ActivityTaskFailed.getDescriptor().findFieldByName("activity_task_created_event_id"),
                        ChildRunCompleted.getDescriptor().findFieldByName("child_run_created_event_id"),
                        ChildRunFailed.getDescriptor().findFieldByName("child_run_created_event_id"),
                        TimerElapsed.getDescriptor().findFieldByName("timer_created_event_id")))
                // Register message types that are used in Any fields.
                .usingTypeRegistry(
                        JsonFormat.TypeRegistry.newBuilder()
                                .add(ArgumentArtifact.getDescriptor().getMessageTypes())
                                .add(ArgumentCommon.getDescriptor().getMessageTypes())
                                .add(ArgumentMetrics.getDescriptor().getMessageTypes())
                                .add(ArgumentNotification.getDescriptor().getMessageTypes())
                                .add(ArgumentPackageMetadata.getDescriptor().getMessageTypes())
                                .add(ArgumentVulnanalysis.getDescriptor().getMessageTypes())
                                .add(ArgumentVulnDataSource.getDescriptor().getMessageTypes())
                                .add(ArgumentVulnPolicy.getDescriptor().getMessageTypes())
                                .add(ResultVulnanalysis.getDescriptor().getMessageTypes())
                                .build());
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getWorkflowInstance(String id) {
        final WorkflowRunMetadata runMetadata = dexEngine.getRunMetadataByInstanceId(id);
        if (runMetadata == null) {
            throw new NotFoundException();
        }

        return Response.ok(convert(runMetadata)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listWorkflowRuns(
            @Nullable String workflowName,
            @Nullable Integer workflowVersion,
            @Nullable String workflowInstanceId,
            @Nullable WorkflowRunStatus status,
            @Nullable List<String> label,
            @Nullable Long createdSince,
            @Nullable Long createdBefore,
            @Nullable Long completedSince,
            @Nullable Long completedBefore,
            Integer limit,
            @Nullable String pageToken,
            @Nullable SortDirection sortDirection,
            @Nullable String sortBy) {
        final Page<WorkflowRunMetadata> runsPage = dexEngine.listRuns(
                new ListWorkflowRunsRequest()
                        .withWorkflowName(workflowName)
                        .withWorkflowVersion(workflowVersion)
                        .withWorkflowInstanceId(workflowInstanceId)
                        .withStatuses(status != null ? Set.of(convert(status)) : null)
                        .withLabels(convertLabelFilters(label))
                        .withCreatedSince(createdSince != null
                                ? Instant.ofEpochMilli(createdSince)
                                : null)
                        .withCreatedBefore(createdBefore != null
                                ? Instant.ofEpochMilli(createdBefore)
                                : null)
                        .withCompletedSince(completedSince != null
                                ? Instant.ofEpochMilli(completedSince)
                                : null)
                        .withCompletedBefore(completedBefore != null
                                ? Instant.ofEpochMilli(completedBefore)
                                : null)
                        .withSortBy(switch (sortBy) {
                            case "id" -> ListWorkflowRunsRequest.SortBy.ID;
                            case "created_at" -> ListWorkflowRunsRequest.SortBy.CREATED_AT;
                            case "completed_at" -> ListWorkflowRunsRequest.SortBy.COMPLETED_AT;
                            case null, default -> null;
                        })
                        .withSortDirection(mapSortDirection(sortDirection))
                        .withPageToken(pageToken)
                        .withLimit(limit));

        final var response = ListWorkflowRunsResponse.builder()
                .items(runsPage.items().stream()
                        .map(WorkflowsResource::convert)
                        .toList())
                .nextPageToken(runsPage.nextPageToken())
                .total(convertTotalCount(runsPage.totalCount()))
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getWorkflowRun(UUID id) {
        final WorkflowRunMetadata runMetadata = dexEngine.getRunMetadataById(id);
        if (runMetadata == null) {
            throw new NotFoundException();
        }

        return Response.ok(convert(runMetadata)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listWorkflowRunEvents(
            UUID id,
            @Nullable Integer fromSequenceNumber,
            Integer limit,
            @Nullable String pageToken,
            @Nullable SortDirection sortDirection) {
        final Page<WorkflowRunHistoryEntry> historyEntryPage =
                dexEngine.listRunHistory(
                        new ListWorkflowRunHistoryRequest(id)
                                .withFromSequenceNumber(fromSequenceNumber)
                                .withSortDirection(mapSortDirection(sortDirection))
                                .withPageToken(pageToken)
                                .withLimit(limit));

        final var response = ListWorkflowRunEventsResponse.builder()
                .items(historyEntryPage.items().stream()
                        .map(entry -> convert(entry, eventJsonPrinter, objectMapper))
                        .toList())
                .nextPageToken(historyEntryPage.nextPageToken())
                .total(convertTotalCount(historyEntryPage.totalCount()))
                .build();

        return Response.ok(response).build();
    }

    private static org.dependencytrack.dex.engine.api.@Nullable WorkflowRunStatus convert(@Nullable WorkflowRunStatus status) {
        return switch (status) {
            case CANCELLED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.CANCELLED;
            case COMPLETED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.COMPLETED;
            case FAILED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.FAILED;
            case CREATED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.CREATED;
            case RUNNING -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.RUNNING;
            case SUSPENDED -> org.dependencytrack.dex.engine.api.WorkflowRunStatus.SUSPENDED;
            case null -> null;
        };
    }

    private static WorkflowRunStatus convert(org.dependencytrack.dex.engine.api.WorkflowRunStatus status) {
        return switch (status) {
            case CANCELLED -> WorkflowRunStatus.CANCELLED;
            case COMPLETED -> WorkflowRunStatus.COMPLETED;
            case FAILED -> WorkflowRunStatus.FAILED;
            case CREATED -> WorkflowRunStatus.CREATED;
            case RUNNING -> WorkflowRunStatus.RUNNING;
            case SUSPENDED -> WorkflowRunStatus.SUSPENDED;
        };
    }

    private static @Nullable Map<String, String> convertLabelFilters(@Nullable List<String> labelFilters) {
        if (labelFilters == null || labelFilters.isEmpty()) {
            return null;
        }

        final var labels = new HashMap<String, String>(labelFilters.size());
        for (final String entry : labelFilters) {
            // NB: format is already validated via @Pattern annotation in
            // the WorkflowsApi interface.
            final int eq = entry.indexOf('=');
            labels.put(entry.substring(0, eq), entry.substring(eq + 1));
        }

        return labels;
    }

    private static org.dependencytrack.api.v2.model.WorkflowRunMetadata convert(WorkflowRunMetadata runMetadata) {
        return org.dependencytrack.api.v2.model.WorkflowRunMetadata.builder()
                .id(runMetadata.id())
                .parentId(runMetadata.parentId())
                .workflowName(runMetadata.workflowName())
                .workflowVersion(runMetadata.workflowVersion())
                .workflowInstanceId(runMetadata.workflowInstanceId())
                .taskQueueName(runMetadata.taskQueueName())
                .status(convert(runMetadata.status()))
                .priority(runMetadata.priority())
                .concurrencyKey(runMetadata.concurrencyKey())
                .labels(runMetadata.labels())
                .createdAt(runMetadata.createdAt().toEpochMilli())
                .updatedAt(runMetadata.updatedAt() != null
                        ? runMetadata.updatedAt().toEpochMilli()
                        : null)
                .startedAt(runMetadata.startedAt() != null
                        ? runMetadata.startedAt().toEpochMilli()
                        : null)
                .completedAt(runMetadata.completedAt() != null
                        ? runMetadata.completedAt().toEpochMilli()
                        : null)
                .build();
    }

    private static ListWorkflowRunEventsResponseItem convert(
            WorkflowRunHistoryEntry entry,
            JsonFormat.Printer eventJsonPrinter,
            ObjectMapper objectMapper) {
        final Map<String, Object> eventJsonMap;
        try {
            final String eventJson = eventJsonPrinter.print(entry.event());
            eventJsonMap = objectMapper.readValue(eventJson, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return ListWorkflowRunEventsResponseItem.builder()
                .sequenceNumber(entry.sequenceNumber())
                .event(eventJsonMap)
                .build();
    }

}
