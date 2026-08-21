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
package org.dependencytrack.analysis;

import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CountWorkflowRunsRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.response.CreateWorkflowRunResponse;
import org.dependencytrack.proto.internal.workflow.v1.AnalyzeProjectWorkflowArg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_ANALYSIS_TRIGGER;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger.ANALYSIS_TRIGGER_SCHEDULE;

/// @since 5.1.0
public final class PortfolioAnalysisTask implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(PortfolioAnalysisTask.class);
    private static final String TRIGGER_LABEL_VALUE =
            AnalyzeProjectWorkflow.triggerLabelValue(ANALYSIS_TRIGGER_SCHEDULE);

    private final DexEngine dexEngine;
    private final int maxRunsInFlight;
    private final Duration maxAnalysisAge;

    public PortfolioAnalysisTask(DexEngine dexEngine, int maxRunsInFlight, Duration maxAnalysisAge) {
        if (maxRunsInFlight < 1) {
            throw new IllegalArgumentException("maxRunsInFlight must be positive");
        }
        requireNonNull(maxAnalysisAge, "maxAnalysisAge must not be null");
        if (maxAnalysisAge.isZero() || maxAnalysisAge.isNegative()) {
            throw new IllegalArgumentException("maxAnalysisAge must be positive");
        }
        this.dexEngine = requireNonNull(dexEngine, "dexEngine must not be null");
        this.maxRunsInFlight = maxRunsInFlight;
        this.maxAnalysisAge = maxAnalysisAge;
    }

    @Override
    public void run() {
        final long runsInFlight = dexEngine.countRuns(new CountWorkflowRunsRequest(
                AnalyzeProjectWorkflow.class,
                WorkflowRunStatus.NON_TERMINAL_STATUSES,
                Map.of(WF_LABEL_ANALYSIS_TRIGGER, TRIGGER_LABEL_VALUE),
                /* limit */ maxRunsInFlight));

        final int capacity = Math.toIntExact(maxRunsInFlight - runsInFlight);
        if (capacity < 1) {
            LOGGER.debug("At the limit of {} analyses in flight", maxRunsInFlight);
            return;
        }

        final Instant now = Instant.now();
        final List<ProjectDueForAnalysis> projects = withJdbiHandle(handle ->
                handle.attach(ProjectLastAnalysisDao.class).getProjectsDue(now.minus(maxAnalysisAge), capacity));
        if (projects.isEmpty()) {
            LOGGER.debug("No projects due for analysis");
            return;
        }

        final var projectIdByRequestId = new HashMap<UUID, Long>(projects.size());
        final var requests = new ArrayList<CreateWorkflowRunRequest<?>>(projects.size());
        for (final ProjectDueForAnalysis project : projects) {
            final var request = new CreateWorkflowRunRequest<>(AnalyzeProjectWorkflow.class)
                    .withWorkflowInstanceId(AnalyzeProjectWorkflow.instanceIdForScheduled(project.uuid()))
                    .withConcurrencyKey(AnalyzeProjectWorkflow.concurrencyKeyForProject(project.uuid()))
                    .withLabels(Map.ofEntries(
                            Map.entry(WF_LABEL_PROJECT_UUID, project.uuid().toString()),
                            Map.entry(WF_LABEL_ANALYSIS_TRIGGER, TRIGGER_LABEL_VALUE)))
                    .withArgument(AnalyzeProjectWorkflowArg.newBuilder()
                            .setProjectUuid(project.uuid().toString())
                            .setTrigger(ANALYSIS_TRIGGER_SCHEDULE)
                            .build());

            projectIdByRequestId.put(request.requestId(), project.id());
            requests.add(request);
        }

        final List<CreateWorkflowRunResponse> responses = dexEngine.createRuns(requests);

        // The engine drops a request when an analysis for the project is still in progress.
        // Those projects keep their old timestamp, so the next tick offers them again.
        final long[] analyzedProjectIds = responses.stream()
                .map(CreateWorkflowRunResponse::requestId)
                .map(projectIdByRequestId::get)
                .filter(Objects::nonNull)
                .mapToLong(Long::longValue)
                .toArray();

        inJdbiTransaction(handle -> handle.attach(ProjectLastAnalysisDao.class).recordAttempt(analyzedProjectIds, now));

        LOGGER.info(
                "Started analysis for {} of {} offered projects; {} were already in flight",
                analyzedProjectIds.length,
                projects.size(),
                runsInFlight);
    }
}
