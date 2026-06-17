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
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.proto.v1.BomProcessingFailedSubject;
import org.dependencytrack.persistence.DatabaseSeedingInitTask;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.dependencytrack.proto.internal.workflow.v1.ImportBomArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.apache.commons.io.IOUtils.resourceToURL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_BOM_UPLOAD_TOKEN;
import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.model.ConfigPropertyConstants.ACCEPT_ARTIFACT_CYCLONEDX;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_CONSUMED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSED;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_BOM_PROCESSING_FAILED;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_ERROR;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.mockito.Mockito.mock;

class ImportBomWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest
            = new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private FileStorage fileStorage;

    @BeforeEach
    void beforeEach() {
        fileStorage = new MemoryFileStorage();

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new ImportBomWorkflow(),
                protoConverter(ImportBomArg.class),
                voidConverter(),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new ImportBomActivity(
                        fileStorage, mock(DexEngine.class), false),
                protoConverter(ImportBomArg.class),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.registerActivity(
                new DeleteFilesActivity(fileStorage),
                protoConverter(DeleteFilesArgument.class),
                voidConverter(),
                Duration.ofSeconds(5));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "artifact-imports", 1));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-artifact-imports", "artifact-imports", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();

        qm.createConfigProperty(
                ACCEPT_ARTIFACT_CYCLONEDX.getGroupName(),
                ACCEPT_ARTIFACT_CYCLONEDX.getPropertyName(),
                "true",
                ACCEPT_ARTIFACT_CYCLONEDX.getPropertyType(),
                ACCEPT_ARTIFACT_CYCLONEDX.getDescription());

        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
    }

    @Test
    void shouldProcessBomSuccessfully() throws Exception {
        useJdbiTransaction(DatabaseSeedingInitTask::seedDefaultLicenses);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var bomFileMetadata = storeBomFile("bom-1.xml");
        final var bomUploadToken = UUID.randomUUID();
        final var runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ImportBomWorkflow.class)
                        .withLabels(Map.ofEntries(
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, bomUploadToken.toString()),
                                Map.entry(WF_LABEL_PROJECT_UUID, project.getUuid().toString())))
                        .withArgument(ImportBomArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .setProjectName(project.getName())
                                .setProjectVersion(project.getVersion() != null ? project.getVersion() : "")
                                .setBomUploadToken(bomUploadToken.toString())
                                .setBomFileMetadata(bomFileMetadata)
                                .build()));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(60));

        assertThat(qm.getNotificationOutbox())
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED))
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getClassifier()).isEqualTo(Classifier.APPLICATION);
        assertThat(project.getLastBomImport()).isNotNull();
        assertThat(project.getLastBomImportFormat()).isEqualTo("CycloneDX 1.5");

        final List<Component> components = qm.getAllComponents(project);
        assertThat(components).hasSize(1);
    }

    @Test
    void shouldCleanUpFilesOnFailure() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var bomFileMetadata = storeBomFile("bom-invalid.json");
        final var bomUploadToken = UUID.randomUUID();
        final var runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ImportBomWorkflow.class)
                        .withLabels(Map.ofEntries(
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, bomUploadToken.toString()),
                                Map.entry(WF_LABEL_PROJECT_UUID, project.getUuid().toString())))
                        .withArgument(ImportBomArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .setProjectName(project.getName())
                                .setProjectVersion(project.getVersion() != null ? project.getVersion() : "")
                                .setBomUploadToken(bomUploadToken.toString())
                                .setBomFileMetadata(bomFileMetadata)
                                .build()));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED, Duration.ofSeconds(60));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSING_FAILED);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_ERROR);
            assertThat(notification.hasSubject()).isTrue();
            assertThat(notification.getSubject().is(BomProcessingFailedSubject.class)).isTrue();
        });

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getLastBomImport()).isNull();
    }

    @Test
    void shouldProcessEmptyBom() throws Exception {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        final var bomFileMetadata = storeBomFile("bom-empty.json");
        final var bomUploadToken = UUID.randomUUID();
        final var runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(ImportBomWorkflow.class)
                        .withLabels(Map.ofEntries(
                                Map.entry(WF_LABEL_BOM_UPLOAD_TOKEN, bomUploadToken.toString()),
                                Map.entry(WF_LABEL_PROJECT_UUID, project.getUuid().toString())))
                        .withArgument(ImportBomArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .setProjectName(project.getName())
                                .setProjectVersion(project.getVersion() != null ? project.getVersion() : "")
                                .setBomUploadToken(bomUploadToken.toString())
                                .setBomFileMetadata(bomFileMetadata)
                                .build()));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED, Duration.ofSeconds(60));

        assertThat(qm.getNotificationOutbox())
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_CONSUMED))
                .anySatisfy(notification -> assertThat(notification.getGroup()).isEqualTo(GROUP_BOM_PROCESSED));

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getLastBomImport()).isNotNull();

        assertThat(qm.getAllComponents(project)).isEmpty();
    }

    private FileMetadata storeBomFile(final String testFileName) throws Exception {
        final var bomFilePath = Paths.get(resourceToURL("/unit/" + testFileName).toURI());

        try (final var fileInputStream = Files.newInputStream(bomFilePath)) {
            return fileStorage.store(
                    "test/%s-%s".formatted(ImportBomWorkflowTest.class.getSimpleName(), UUID.randomUUID()),
                    fileInputStream);
        }
    }

}
