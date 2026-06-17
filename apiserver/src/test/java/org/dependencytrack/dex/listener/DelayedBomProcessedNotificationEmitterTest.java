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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.proto.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.notification.proto.v1.BomProcessingFailedSubject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;

class DelayedBomProcessedNotificationEmitterTest extends PersistenceCapableTest {

    private DelayedBomProcessedNotificationEmitter emitter;

    @BeforeEach
    void beforeEach() {
        emitter = new DelayedBomProcessedNotificationEmitter();
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
    }

    @Test
    void shouldEmitBomProcessedNotificationForCompletedRun() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final UUID bomUploadToken = UUID.randomUUID();

        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, project.getUuid().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, bomUploadToken.toString()))))));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.hasSubject()).isTrue();
            assertThat(notification.getSubject().is(BomConsumedOrProcessedSubject.class)).isTrue();
            final var subject = notification.getSubject().unpack(BomConsumedOrProcessedSubject.class);
            assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid().toString());
            assertThat(subject.getToken()).isEqualTo(bomUploadToken.toString());
            assertThat(subject.getBom().getFormat()).isEqualTo("CycloneDX");
            assertThat(subject.getBom().getSpecVersion()).isEqualTo("Unknown");
        });
    }

    @Test
    void shouldEmitBomProcessingFailedNotificationForFailedRun() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final UUID bomUploadToken = UUID.randomUUID();

        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata("vuln-analysis", WorkflowRunStatus.FAILED,
                        Map.of(WF_LABEL_PROJECT_UUID, project.getUuid().toString(),
                                WF_LABEL_BOM_UPLOAD_TOKEN, bomUploadToken.toString())))));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_ERROR);
            assertThat(notification.hasSubject()).isTrue();
            assertThat(notification.getSubject().is(BomProcessingFailedSubject.class)).isTrue();
            final var subject = notification.getSubject().unpack(BomProcessingFailedSubject.class);
            assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid().toString());
            assertThat(subject.getToken()).isEqualTo(bomUploadToken.toString());
            assertThat(subject.getCause()).isEqualTo("Vulnerability analysis failed");
        });
    }

    @Test
    void shouldEmitNotificationsForMultipleRuns() {
        final var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);

        final var tokenA = UUID.randomUUID();
        final var tokenB = UUID.randomUUID();

        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, projectA.getUuid().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, tokenA.toString()))),
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.FAILED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, projectB.getUuid().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, tokenB.toString()))))));

        assertThat(qm.getNotificationOutbox()).satisfiesExactlyInAnyOrder(
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED),
                notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED));
    }

    @Test
    void shouldIgnoreRunsWithNonMatchingWorkflowName() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "repo-meta-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, project.getUuid().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, UUID.randomUUID().toString()))))));

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void shouldIgnoreRunsWithNoLabels() {
        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        null))));

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void shouldIgnoreRunsWithMissingProjectUuid() {
        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.of(WF_LABEL_BOM_UPLOAD_TOKEN, UUID.randomUUID().toString())))));

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void shouldIgnoreRunsWithMissingBomUploadToken() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.of(WF_LABEL_PROJECT_UUID, project.getUuid().toString())))));

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void shouldSkipRunsForNonExistentProject() {
        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of(
                createRunMetadata(
                        "vuln-analysis",
                        WorkflowRunStatus.COMPLETED,
                        Map.ofEntries(
                                Map.entry(WF_LABEL_PROJECT_UUID, UUID.randomUUID().toString()),
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, UUID.randomUUID().toString()))))));

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void shouldDoNothingForEmptyEvent() {
        emitter.onEvent(new WorkflowRunsCompletedEvent(List.of()));

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    private static WorkflowRunMetadata createRunMetadata(
            String workflowName,
            WorkflowRunStatus status,
            Map<String, String> labels) {
        return new WorkflowRunMetadata(
                UUID.randomUUID(),
                null,
                workflowName,
                1,
                null,
                "default",
                status,
                null,
                0,
                null,
                labels,
                Instant.now(),
                null,
                null,
                null);
    }

}