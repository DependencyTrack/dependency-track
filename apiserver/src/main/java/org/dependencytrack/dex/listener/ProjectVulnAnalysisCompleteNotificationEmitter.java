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
package org.dependencytrack.dex.listener;

import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.event.DexEngineEventListener;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEventListener;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.proto.v1.ComponentVulnAnalysisCompleteSubject;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.notification.proto.v1.ProjectVulnAnalysisStatus;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.vulnanalysis.VulnAnalysisWorkflow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.notification.api.NotificationFactory.createProjectVulnerabilityAnalysisCompleteNotification;
import static org.dependencytrack.notification.proto.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_COMPLETED;
import static org.dependencytrack.notification.proto.v1.ProjectVulnAnalysisStatus.PROJECT_VULN_ANALYSIS_STATUS_FAILED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * A {@link DexEngineEventListener} that emits {@code PROJECT_VULN_ANALYSIS_COMPLETE}
 * notifications upon completion of {@link VulnAnalysisWorkflow} runs.
 *
 * @since 5.0.0
 */
public final class ProjectVulnAnalysisCompleteNotificationEmitter implements WorkflowRunsCompletedEventListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectVulnAnalysisCompleteNotificationEmitter.class);

    @Override
    public void onEvent(WorkflowRunsCompletedEvent event) {
        final var relevantRuns = new ArrayList<RelevantRun>();

        for (final WorkflowRunMetadata runMetadata : event.completedRuns()) {
            if (!"vuln-analysis".equals(runMetadata.workflowName())) {
                continue;
            }

            final Map<String, String> labels = runMetadata.labels();
            if (labels == null) {
                continue;
            }

            final UUID projectUuid = Optional
                    .ofNullable(labels.get(WF_LABEL_PROJECT_UUID))
                    .map(UUID::fromString)
                    .orElse(null);
            if (projectUuid == null) {
                continue;
            }

            final String token = labels.getOrDefault(WF_LABEL_BOM_UPLOAD_TOKEN, "");
            relevantRuns.add(new RelevantRun(projectUuid, token, runMetadata.status()));
        }

        if (relevantRuns.isEmpty()) {
            return;
        }

        final Set<UUID> projectUuids = relevantRuns.stream()
                .map(RelevantRun::projectUuid)
                .collect(Collectors.toSet());

        final Map<UUID, Project> projectSubjectByUuid = withJdbiHandle(
                handle -> handle
                        .attach(NotificationSubjectDao.class)
                        .getProjects(projectUuids)
                        .stream()
                        .collect(Collectors.toMap(
                                project -> UUID.fromString(project.getUuid()),
                                Function.identity())));

        // Only fetch findings for projects with completed runs.
        final Set<UUID> completedProjectUuids = relevantRuns.stream()
                .filter(run -> run.status() == WorkflowRunStatus.COMPLETED)
                .map(RelevantRun::projectUuid)
                .filter(projectSubjectByUuid::containsKey)
                .collect(Collectors.toSet());
        final Map<UUID, List<ComponentVulnAnalysisCompleteSubject>> findingsByProject =
                withJdbiHandle(handle -> handle
                        .attach(NotificationSubjectDao.class)
                        .getForProjectVulnAnalysisComplete(completedProjectUuids));

        final var notifications = new ArrayList<Notification>(relevantRuns.size());
        for (final RelevantRun run : relevantRuns) {
            final Project projectSubject = projectSubjectByUuid.get(run.projectUuid());
            if (projectSubject == null) {
                continue;
            }

            final ProjectVulnAnalysisStatus status =
                    run.status() == WorkflowRunStatus.COMPLETED
                            ? PROJECT_VULN_ANALYSIS_STATUS_COMPLETED
                            : PROJECT_VULN_ANALYSIS_STATUS_FAILED;

            final List<ComponentVulnAnalysisCompleteSubject> findings =
                    run.status() == WorkflowRunStatus.COMPLETED
                            ? findingsByProject.getOrDefault(run.projectUuid(), List.of())
                            : List.of();

            notifications.add(
                    createProjectVulnerabilityAnalysisCompleteNotification(
                            projectSubject,
                            findings,
                            status,
                            run.token()));
        }

        LOGGER.debug("Emitting {} PROJECT_VULN_ANALYSIS_COMPLETE notifications", notifications.size());
        useJdbiTransaction(handle -> new JdbiNotificationEmitter(handle).emitAll(notifications));
    }

    private record RelevantRun(
            UUID projectUuid,
            String token,
            WorkflowRunStatus status) {
    }

}