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
package org.dependencytrack.vulndatasource;

import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.common.pagination.SortDirection;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRun;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.plugin.runtime.NoSuchExtensionException;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.proto.internal.workflow.v1.MirrorVulnDataSourceArg;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_TRIGGERED_BY;

/**
 * @since 5.0.0
 */
public final class VulnDataSourceMirrorService {

    private static final String WORKFLOW_INSTANCE_ID_PREFIX = "mirror-vuln-data-source:";

    private final PluginManager pluginManager;
    private final DexEngine dexEngine;

    public VulnDataSourceMirrorService(PluginManager pluginManager, DexEngine dexEngine) {
        this.pluginManager = requireNonNull(pluginManager, "pluginManager must not be null");
        this.dexEngine = requireNonNull(dexEngine, "dexEngine must not be null");
    }

    public sealed interface TriggerResult {

        record Triggered(UUID runId) implements TriggerResult {
        }

        record AlreadyRunning() implements TriggerResult {
        }

        record NotEnabled() implements TriggerResult {
        }

        record NotFound() implements TriggerResult {
        }

    }

    public TriggerResult trigger(String dataSourceName, @Nullable String triggeredBy) {
        final VulnDataSourceFactory factory;
        try {
            factory = pluginManager.getFactory(VulnDataSource.class, dataSourceName);
        } catch (NoSuchExtensionException e) {
            return new TriggerResult.NotFound();
        }

        if (!factory.isDataSourceEnabled()) {
            return new TriggerResult.NotEnabled();
        }

        CreateWorkflowRunRequest<MirrorVulnDataSourceArg> request =
                new CreateWorkflowRunRequest<>(MirrorVulnDataSourceWorkflow.class)
                        .withWorkflowInstanceId(workflowInstanceId(dataSourceName))
                        .withArgument(MirrorVulnDataSourceArg.newBuilder()
                                .setDataSourceName(dataSourceName)
                                .setSourceName(dataSourceName.toUpperCase(Locale.ROOT))
                                .build());
        if (triggeredBy != null) {
            request = request.withLabels(Map.of(WF_LABEL_TRIGGERED_BY, triggeredBy));
        }

        final UUID runId = dexEngine.createRun(request);
        if (runId == null) {
            return new TriggerResult.AlreadyRunning();
        }

        return new TriggerResult.Triggered(runId);
    }

    public record MirrorStatus(
            Status status,
            @Nullable Instant startedAt,
            @Nullable Instant completedAt,
            @Nullable String failureReason) {

        public enum Status {

            PENDING,
            RUNNING,
            COMPLETED,
            FAILED;

            private static Status of(WorkflowRunStatus runStatus) {
                return switch (runStatus) {
                    case CREATED, SUSPENDED -> MirrorStatus.Status.PENDING;
                    case RUNNING -> MirrorStatus.Status.RUNNING;
                    case COMPLETED -> MirrorStatus.Status.COMPLETED;
                    case CANCELLED, FAILED -> MirrorStatus.Status.FAILED;
                };
            }

        }

    }

    public @Nullable MirrorStatus getLatestStatus(String dataSourceName) {
        try {
            pluginManager.getFactory(VulnDataSource.class, dataSourceName);
        } catch (NoSuchExtensionException e) {
            return null;
        }

        final Page<WorkflowRunMetadata> runsPage = dexEngine.listRuns(
                new ListWorkflowRunsRequest()
                        .withWorkflowInstanceId(workflowInstanceId(dataSourceName))
                        .withSortBy(ListWorkflowRunsRequest.SortBy.CREATED_AT)
                        .withSortDirection(SortDirection.DESC)
                        .withLimit(1));
        if (runsPage.items().isEmpty()) {
            return null;
        }

        final WorkflowRunMetadata runMetadata = runsPage.items().getFirst();
        final String failureReason = switch (runMetadata.status()) {
            case FAILED -> extractFailureReason(runMetadata.id());
            case CANCELLED -> "Cancelled";
            default -> null;
        };

        return new MirrorStatus(
                MirrorStatus.Status.of(runMetadata.status()),
                runMetadata.startedAt(),
                runMetadata.completedAt(),
                failureReason);
    }

    private @Nullable String extractFailureReason(UUID runId) {
        final WorkflowRun run = dexEngine.getRunById(runId);
        if (run == null || run.failure() == null) {
            return null;
        }

        return switch (run.failure().getFailureDetailsCase()) {
            case ACTIVITY_FAILURE_DETAILS,
                 CHILD_WORKFLOW_FAILURE_DETAILS -> {
                if (!run.failure().hasCause()) {
                    yield "Unknown failure";
                }
                
                final String causeMessage = run.failure().getCause().getMessage();
                yield causeMessage.isEmpty() ? "Unknown failure" : causeMessage;
            }
            default -> run.failure().getMessage();
        };
    }

    private static String workflowInstanceId(String dataSourceName) {
        return WORKFLOW_INSTANCE_ID_PREFIX + dataSourceName;
    }

}
