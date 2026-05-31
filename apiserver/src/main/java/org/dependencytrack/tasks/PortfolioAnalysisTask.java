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
package org.dependencytrack.tasks;

import org.dependencytrack.analysis.AnalyzeProjectWorkflow;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.proto.internal.workflow.v1.AnalyzeProjectWorkflowArg;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger.ANALYSIS_TRIGGER_SCHEDULE;

/**
 * Submits all projects in the entire portfolio for analysis.
 */
public final class PortfolioAnalysisTask implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(PortfolioAnalysisTask.class);

    private final DexEngine dexEngine;

    public PortfolioAnalysisTask(DexEngine dexEngine) {
        this.dexEngine = dexEngine;
    }

    @Override
    public void run() {
        List<Project> projectsPage = getProjectsPage(null);
        while (!projectsPage.isEmpty()) {
            if (Thread.currentThread().isInterrupted()) {
                LOGGER.warn("Interrupted before all projects could be processed");
                break;
            }

            final var createWorkflowRunRequests =
                    new ArrayList<CreateWorkflowRunRequest<?>>(projectsPage.size());
            for (final Project project : projectsPage) {
                createWorkflowRunRequests.add(
                        new CreateWorkflowRunRequest<>(AnalyzeProjectWorkflow.class)
                                .withWorkflowInstanceId("analyze-project-scheduled:" + project.uuid())
                                .withConcurrencyKey("analyze-project:" + project.uuid())
                                .withLabels(Map.of(WF_LABEL_PROJECT_UUID, project.uuid().toString()))
                                .withArgument(
                                        AnalyzeProjectWorkflowArg.newBuilder()
                                                .setProjectUuid(project.uuid().toString())
                                                .setTrigger(ANALYSIS_TRIGGER_SCHEDULE)
                                                .build()));
            }

            LOGGER.info("Scheduling vulnerability analysis for {} project(s)", createWorkflowRunRequests.size());
            dexEngine.createRuns(createWorkflowRunRequests);

            projectsPage = getProjectsPage(projectsPage.getLast());
        }
    }

    public record Project(long id, UUID uuid) {
    }

    private List<Project> getProjectsPage(@Nullable Project lastProject) {
        return withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "ID"
                             , "UUID"
                          FROM "PROJECT"
                         WHERE "INACTIVE_SINCE" IS NULL
                        <#if lastId>
                           AND "ID" > :lastId
                        </#if>
                         ORDER BY "ID"
                         LIMIT 1000
                        """)
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .bind("lastId", lastProject != null ? lastProject.id() : null)
                .defineNamedBindings()
                .map((rs, _) -> new Project(
                        rs.getLong(1),
                        rs.getObject(2, UUID.class)))
                .list());
    }

}
