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

import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.activity.DeleteFilesActivity;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.filestorage.api.FileStorage;
import org.dependencytrack.filestorage.memory.MemoryFileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.dependencytrack.proto.internal.workflow.v1.ImportVexArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.apache.commons.io.IOUtils.resourceToURL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_VEX_UPLOAD_TOKEN;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_VEX_CONSUMED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_VEX_PROCESSED;

class ImportVexWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private FileStorage fileStorage;

    @BeforeEach
    void beforeEach() {
        fileStorage = new MemoryFileStorage();

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new ImportVexWorkflow(), protoConverter(ImportVexArg.class), voidConverter(), Duration.ofSeconds(5));
        engine.registerActivity(
                new ImportVexActivity(fileStorage), protoConverter(ImportVexArg.class), voidConverter());
        engine.registerActivity(
                new DeleteFilesActivity(fileStorage), protoConverter(DeleteFilesArgument.class), voidConverter());

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "artifact-imports", 1));

        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-artifact-imports", "artifact-imports", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();

        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
    }

    @Test
    void shouldProcessVexSuccessfully() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var vexFileMetadata = storeVexFile("vex-issue2549.json");

        final var runId = startWorkflow(project, vexFileMetadata);
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(qm.getNotificationOutbox())
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_VEX_CONSUMED))
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_VEX_PROCESSED));

        assertThatThrownBy(() -> fileStorage.get(vexFileMetadata)).isInstanceOf(NoSuchFileException.class);
    }

    @Test
    void shouldProcessOpenVexSuccessfully() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var component = new org.dependencytrack.model.Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        component.setPurl("pkg:maven/com.acme/acme-lib@1.0.0");
        qm.createComponent(component, false);

        var vulnerability = new org.dependencytrack.model.Vulnerability();
        vulnerability.setVulnId("CVE-2099-0001");
        vulnerability.setSource(org.dependencytrack.model.Vulnerability.Source.NVD);
        vulnerability.setSeverity(org.dependencytrack.model.Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);
        qm.addVulnerability(vulnerability, component, "none");

        final var vexFileMetadata = fileStorage.store(
                "test/%s-%s".formatted(ImportVexWorkflowTest.class.getSimpleName(), UUID.randomUUID()),
                new ByteArrayInputStream(/* language=JSON */ """
                        {
                          "@context": "https://openvex.dev/ns/v0.2.0",
                          "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                          "author": "Wolfi J Inkinson",
                          "timestamp": "2023-01-08T18:02:03-06:00",
                          "version": 1,
                          "statements": [
                            {
                              "vulnerability": { "name": "CVE-2099-0001" },
                              "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                              "status": "not_affected",
                              "justification": "vulnerable_code_not_in_execute_path"
                            }
                          ]
                        }
                        """.getBytes()));

        final var runId = startWorkflow(project, vexFileMetadata);
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(qm.getNotificationOutbox())
                .anySatisfy(notification -> {
                    assertThat(notification.getGroup()).isEqualTo(GROUP_VEX_CONSUMED);
                    assertThat(unpackVexSubject(notification).getFormat()).isEqualTo("OpenVEX");
                })
                .anySatisfy(notification -> {
                    assertThat(notification.getGroup()).isEqualTo(GROUP_VEX_PROCESSED);
                    assertThat(unpackVexSubject(notification).getFormat()).isEqualTo("OpenVEX");
                });

        final javax.jdo.Query<org.dependencytrack.model.Vex> vexQuery =
                qm.getPersistenceManager().newQuery(org.dependencytrack.model.Vex.class);
        final List<org.dependencytrack.model.Vex> vexes = vexQuery.executeList();
        assertThat(vexes).hasSize(1);
        assertThat(vexes.getFirst().getVexFormat()).isEqualTo("OpenVEX");
        assertThat(vexes.getFirst().getSpecVersion()).isEqualTo("0.2.0");
        assertThat(vexes.getFirst().getVexVersion()).isEqualTo(1);
        assertThat(vexes.getFirst().getSerialNumber()).isNull();

        final org.dependencytrack.model.Analysis analysis =
                qm.getAnalysis(component, vulnerability);
        assertThat(analysis)
                .extracting(org.dependencytrack.model.Analysis::getAnalysisState,
                        org.dependencytrack.model.Analysis::isSuppressed)
                .containsExactly(org.dependencytrack.model.AnalysisState.NOT_AFFECTED, true);

        assertThatThrownBy(() -> fileStorage.get(vexFileMetadata))
                .isInstanceOf(NoSuchFileException.class);
    }

    @Test
    void shouldFailWhenOpenVexCannotBeParsed() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var vexFileMetadata = fileStorage.store(
                "test/%s-%s".formatted(ImportVexWorkflowTest.class.getSimpleName(), UUID.randomUUID()),
                new ByteArrayInputStream(/* language=JSON */ """
                        {
                          "@context": "https://openvex.dev/ns/v0.2.0",
                          "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
                          "timestamp": "2023-01-08T18:02:03-06:00",
                          "version": 1,
                          "statements": [
                            {
                              "vulnerability": { "name": "CVE-2099-0001" },
                              "products": [{ "@id": "pkg:maven/com.acme/acme-lib@1.0.0" }],
                              "status": "fixed"
                            }
                          ]
                        }
                        """.getBytes()));

        final var runId = startWorkflow(project, vexFileMetadata);
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(qm.getNotificationOutbox()).isEmpty();
        assertThatThrownBy(() -> fileStorage.get(vexFileMetadata))
                .isInstanceOf(NoSuchFileException.class);
    }

    @Test
    void shouldFailWhenVexCannotBeParsed() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var vexFileMetadata = fileStorage.store(
                "test/%s-%s".formatted(ImportVexWorkflowTest.class.getSimpleName(), UUID.randomUUID()),
                new ByteArrayInputStream(
                        "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.4\",\"unterminated".getBytes()));

        final var runId = startWorkflow(project, vexFileMetadata);
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(qm.getNotificationOutbox()).isEmpty();
        assertThatThrownBy(() -> fileStorage.get(vexFileMetadata)).isInstanceOf(NoSuchFileException.class);
    }

    @Test
    void shouldFailWhenProjectDoesNotExist() throws Exception {
        final var vexFileMetadata = storeVexFile("vex-issue2549.json");
        final var unknownProjectUuid = UUID.randomUUID();
        final var vexUploadToken = UUID.randomUUID();

        final var runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ImportVexWorkflow.class)
                        .withLabels(Map.ofEntries(
                                Map.entry(WF_LABEL_VEX_UPLOAD_TOKEN, vexUploadToken.toString()),
                                Map.entry(WF_LABEL_PROJECT_UUID, unknownProjectUuid.toString())))
                        .withArgument(ImportVexArg.newBuilder()
                                .setProjectUuid(unknownProjectUuid.toString())
                                .setProjectName("Acme Example")
                                .setProjectVersion("1.0")
                                .setVexUploadToken(vexUploadToken.toString())
                                .setVexFileMetadata(vexFileMetadata)
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        assertThat(qm.getNotificationOutbox()).isEmpty();
        assertThatThrownBy(() -> fileStorage.get(vexFileMetadata)).isInstanceOf(NoSuchFileException.class);
    }

    private UUID startWorkflow(Project project, FileMetadata vexFileMetadata) {
        return workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ImportVexWorkflow.class)
                        .withArgument(ImportVexArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .setProjectName(project.getName())
                                .setProjectVersion(project.getVersion() != null ? project.getVersion() : "")
                                .setVexUploadToken(UUID.randomUUID().toString())
                                .setVexFileMetadata(vexFileMetadata)
                                .build()));
    }

    private static org.dependencytrack.notification.proto.v1.VexConsumedOrProcessedSubject unpackVexSubject(
            final org.dependencytrack.notification.proto.v1.Notification notification) {
        try {
            return notification.getSubject().unpack(org.dependencytrack.notification.proto.v1.VexConsumedOrProcessedSubject.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private FileMetadata storeVexFile(String testFileName) throws Exception {
        final var vexFilePath = Paths.get(resourceToURL("/unit/" + testFileName).toURI());

        try (final var fileInputStream = Files.newInputStream(vexFilePath)) {
            return fileStorage.store(
                    "test/%s-%s".formatted(ImportVexWorkflowTest.class.getSimpleName(), UUID.randomUUID()),
                    fileInputStream);
        }
    }
}
