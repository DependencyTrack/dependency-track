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
package org.dependencytrack.vulnanalysis;

import io.github.resilience4j.core.IntervalFunction;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.cyclonedx.proto.v1_7.VulnerabilityReference;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.cache.api.NoopCacheManager;
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
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AppliedPolicyAnnotation;
import org.dependencytrack.model.PolicyAnnotation;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.FindingDao;
import org.dependencytrack.persistence.jdbi.FindingDao.FindingRow;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.policy.cel.CelVulnerabilityPolicyEvaluator;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyOperation;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyRating;
import org.dependencytrack.proto.internal.workflow.v1.DeleteFilesArgument;
import org.dependencytrack.proto.internal.workflow.v1.InvokeVulnAnalyzerArg;
import org.dependencytrack.proto.internal.workflow.v1.InvokeVulnAnalyzerRes;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisArg;
import org.dependencytrack.proto.internal.workflow.v1.PrepareVulnAnalysisRes;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg;
import org.dependencytrack.proto.internal.workflow.v1.VulnAnalysisWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.VulnAnalysisWorkflowContext;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.internal.InternalVulnAnalyzerConfigV1;
import org.dependencytrack.vulnanalysis.internal.InternalVulnAnalyzerPlugin;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABILITY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABLE_DEPENDENCY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_VULNERABILITY_RETRACTED;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class VulnAnalysisWorkflowTest extends PersistenceCapableTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest
            = new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private FileStorage fileStorage;
    private PluginManager pluginManager;
    private final AtomicReference<Function<Bom, Bom>> mockAnalyzerFunction =
            new AtomicReference<>(bom -> Bom.getDefaultInstance());

    @BeforeEach
    void beforeEach() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        fileStorage = new MemoryFileStorage();

        final var mockAnalyzerPlugin = new MockVulnAnalyzerPlugin(bom -> mockAnalyzerFunction.get().apply(bom));

        pluginManager = new PluginManager(
                new SmallRyeConfigBuilder()
                        .withDefaultValue("dt.vuln-analyzer.internal.datasource.name", "default")
                        .build(),
                new NoopCacheManager(),
                secretName -> null,
                JdbiFactory.createJdbi(),
                HttpClient.newHttpClient(),
                List.of(VulnAnalyzer.class, VulnDataSource.class));
        pluginManager.loadPlugins(List.of(
                new InternalVulnAnalyzerPlugin(),
                mockAnalyzerPlugin));

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new VulnAnalysisWorkflow(),
                protoConverter(VulnAnalysisWorkflowArg.class),
                voidConverter(),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new DeleteFilesActivity(fileStorage),
                protoConverter(DeleteFilesArgument.class),
                voidConverter(),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new InvokeVulnAnalyzerActivity(fileStorage, pluginManager),
                protoConverter(InvokeVulnAnalyzerArg.class),
                protoConverter(InvokeVulnAnalyzerRes.class),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new PrepareVulnAnalysisActivity(fileStorage, pluginManager),
                protoConverter(PrepareVulnAnalysisArg.class),
                protoConverter(PrepareVulnAnalysisRes.class),
                Duration.ofSeconds(5));
        engine.registerActivity(
                new ReconcileVulnAnalysisResultsActivity(
                        fileStorage,
                        pluginManager,
                        new CelVulnerabilityPolicyEvaluator()),
                protoConverter(ReconcileVulnAnalysisResultsArg.class),
                voidConverter(),
                Duration.ofSeconds(5));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "vuln-analyses", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "vuln-analysis-reconciliations", 1));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-vuln-analysis", "vuln-analyses", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-vuln-analysis-reconciliation", "vuln-analysis-reconciliations", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @AfterEach
    void afterEach() {
        if (pluginManager != null) {
            pluginManager.close();
        }
    }

    @Test
    void test() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.fasterxml.jackson.core");
        vs.setPurlName("jackson-databind");
        vs.setVersionStartIncluding("2.9.0");
        vs.setVersionEndExcluding("3");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.9.8");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8");
        qm.persist(component);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final List<Vulnerability> vulns = qm.getVulnerabilities(project, true);
        assertThat(vulns).hasSize(1);

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getGroup()).isEqualTo(GROUP_NEW_VULNERABILITY);
        });

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getLastVulnerabilityAnalysis()).isNotNull();
    }

    @Test
    void shouldEmitNewVulnerableDependencyNotification() throws Exception {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.fasterxml.jackson.core");
        vs.setPurlName("jackson-databind");
        vs.setVersionStartIncluding("2.9.0");
        vs.setVersionEndExcluding("3");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.9.8");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8");
        qm.persist(component);

        final var context = VulnAnalysisWorkflowContext.newBuilder()
                .addNewComponentIds(component.getId())
                .build();
        final FileMetadata contextFileMetadata = fileStorage.store(
                "vuln-analysis/context/test.proto",
                "application/protobuf",
                new ByteArrayInputStream(context.toByteArray()));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .setContextFileMetadata(contextFileMetadata)
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(qm.getNotificationOutbox())
                .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                .containsExactlyInAnyOrder(
                        GROUP_NEW_VULNERABILITY,
                        GROUP_NEW_VULNERABLE_DEPENDENCY);
    }

    @Test
    void shouldDeactivateFindingsThatAreNoLongerReported() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.persist(component);

        qm.addVulnerability(vuln, component, "internal");

        final long projectId = project.getId();
        final Supplier<List<FindingRow>> findingsSupplier = () -> withJdbiHandle(
                handle -> handle
                        .attach(FindingDao.class)
                        .getFindingsByProject(
                                projectId,
                                /* includeInactive */ false,
                                /* includeSuppressed */ false,
                                /* searchText */ null,
                                /* hasAnalysis */ null,
                                /* source */ null,
                                /* epssFrom */ null,
                                /* epssTo */ null));

        List<FindingRow> findings = findingsSupplier.get();
        assertThat(findings).hasSize(1);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        findings = findingsSupplier.get();
        assertThat(findings).isEmpty();

        assertThat(qm.getNotificationOutbox())
                .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                .containsExactly(GROUP_VULNERABILITY_RETRACTED);
    }

    @Test
    void shouldEmitVulnerabilityRetractedNotificationWhenFindingBecomesInactive() throws Exception {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-200");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        component = qm.persist(component);

        // Run first analysis to create the finding.
        UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(qm.getNotificationOutbox())
                .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                .containsExactly(GROUP_NEW_VULNERABILITY);
        qm.truncateNotificationOutbox();

        // Remove vulnerable software so the internal analyzer no longer reports the finding.
        qm.delete(vs);

        runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(qm.getNotificationOutbox())
                .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                .containsExactly(GROUP_VULNERABILITY_RETRACTED);

        final org.dependencytrack.notification.proto.v1.Notification notification = qm.getNotificationOutbox().getFirst();
        final var subject = notification.getSubject()
                .unpack(org.dependencytrack.notification.proto.v1.VulnerabilityRetractedSubject.class);
        assertThat(subject.getVulnerability().getVulnId()).isEqualTo("INT-200");
    }

    @Test
    void shouldEmitNewVulnerabilityNotificationWhenFindingBecomesActiveAgain() throws Exception {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-201");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.persist(vuln);

        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        component = qm.persist(component);

        // Create finding directly without VulnerableSoftware.
        // The internal analyzer won't match, so the next run will deactivate it.
        qm.addVulnerability(vuln, component, "internal");

        // Run 1: Internal analyzer finds nothing -> attribution soft-deleted -> finding inactive.
        UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(qm.getNotificationOutbox())
                .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                .containsExactly(GROUP_VULNERABILITY_RETRACTED);
        qm.truncateNotificationOutbox();

        // Add vulnerable software so the internal analyzer can match the component.
        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        // Run 2: Internal analyzer reports finding -> reactivation.
        runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(qm.getNotificationOutbox())
                .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                .containsExactly(GROUP_NEW_VULNERABILITY);

        final org.dependencytrack.notification.proto.v1.Notification notification = qm.getNotificationOutbox().getFirst();
        final var subject = notification.getSubject()
                .unpack(org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject.class);
        assertThat(subject.getVulnerability().getVulnId()).isEqualTo("INT-201");
    }

    @Test
    void analysisThroughPolicyNewAnalysisTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-100");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.CRITICAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        policyAnalysis.setJustification(VulnerabilityPolicyAnalysis.Justification.CODE_NOT_REACHABLE);
        policyAnalysis.setVendorResponse(VulnerabilityPolicyAnalysis.Response.WILL_NOT_FIX);
        policyAnalysis.setDetails("Policy details");

        final var cvssV3Rating = new VulnerabilityPolicyRating();
        cvssV3Rating.setMethod(VulnerabilityPolicyRating.Method.CVSSV3);
        cvssV3Rating.setVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
        cvssV3Rating.setScore(3.7);
        cvssV3Rating.setSeverity(VulnerabilityPolicyRating.Severity.LOW);

        createPolicy("testPolicy", "testAuthor",
                "has(component.name) && project.version != \"\"",
                policyAnalysis, List.of(cvssV3Rating));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(analysis.getAnalysisJustification()).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE);
            assertThat(analysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
            assertThat(analysis.getAnalysisDetails()).isEqualTo("Policy details");
            assertThat(analysis.isSuppressed()).isFalse();
            assertThat(analysis.getSeverity()).isEqualTo(Severity.LOW);
            assertThat(analysis.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
            assertThat(analysis.getCvssV3Score()).isEqualByComparingTo("3.7");
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactly(
                            "Matched on condition: has(component.name) && project.version != \"\"",
                            "Analysis: NOT_SET → NOT_AFFECTED",
                            "Justification: NOT_SET → CODE_NOT_REACHABLE",
                            "Vendor Response: NOT_SET → WILL_NOT_FIX",
                            "Details: Policy details",
                            "Severity: UNASSIGNED → LOW",
                            "CVSSv3 Vector: (None) → CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
                            "CVSSv3 Score: (None) → 3.7");
        });

        assertThat(qm.getNotificationOutbox())
                .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                .containsExactlyInAnyOrder(
                        GROUP_NEW_VULNERABILITY,
                        GROUP_PROJECT_AUDIT_CHANGE);
    }

    @Test
    void analysisThroughPolicyAnnotationsTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-150");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.CRITICAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        policyAnalysis.setAnnotations(List.of(
                new PolicyAnnotation("compliance", "pci-dss"),
                new PolicyAnnotation("owner", "security-team")));

        createPolicy("annotationPolicy", "testAuthor", "true", policyAnalysis, List.of());

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getPolicyAnnotations())
                    .extracting(AppliedPolicyAnnotation::policyName, AppliedPolicyAnnotation::annotator)
                    .containsExactly(tuple("annotationPolicy", "testAuthor"));
            assertThat(analysis.getPolicyAnnotations())
                    .allMatch(annotation -> annotation.appliedAt() != null);
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getCommenter, AnalysisComment::getComment)
                    .contains(tuple(
                            "annotationPolicy",
                            "Policy annotations: (None) → [annotationPolicy (testAuthor)]"));
        });

        assertThat(qm.getNotificationOutbox())
                .filteredOn(notification -> notification.getGroup() == GROUP_PROJECT_AUDIT_CHANGE)
                .singleElement()
                .satisfies(notification -> assertThat(notification.getSubject()
                        .unpack(org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject.class)
                        .getAnalysis()
                        .getPolicyAnnotationsList())
                        .extracting(
                                org.dependencytrack.notification.proto.v1.AppliedPolicyAnnotation::getPolicyName,
                                org.dependencytrack.notification.proto.v1.AppliedPolicyAnnotation::getAnnotator)
                        .containsExactly(tuple("annotationPolicy", "testAuthor")));
    }

    @Test
    void analysisThroughMultiplePoliciesWithSameConditionTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-151");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.CRITICAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        final var policyAnalysisA = new VulnerabilityPolicyAnalysis();
        policyAnalysisA.setState(VulnerabilityPolicyAnalysis.State.EXPLOITABLE);
        policyAnalysisA.setAnnotations(List.of(new PolicyAnnotation("gem", "gem-policy-a")));

        final var policyAnalysisB = new VulnerabilityPolicyAnalysis();
        policyAnalysisB.setState(VulnerabilityPolicyAnalysis.State.EXPLOITABLE);
        policyAnalysisB.setAnnotations(List.of(new PolicyAnnotation("gem", "gem-policy-b")));

        createPolicy("gem-policy-a", "author-a", "true", policyAnalysisA, List.of());
        createPolicy("gem-policy-b", "author-b", "true", policyAnalysisB, List.of());

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getPolicyAnnotations())
                    .extracting(AppliedPolicyAnnotation::policyName, AppliedPolicyAnnotation::annotator)
                    .containsExactlyInAnyOrder(
                            tuple("gem-policy-a", "author-a"),
                            tuple("gem-policy-b", "author-b"));
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getCommenter, AnalysisComment::getComment)
                    .contains(
                            tuple("gem-policy-a", "Policy annotations: (None) → [gem-policy-a (author-a)]"),
                            tuple("gem-policy-b", "Policy annotations: (None) → [gem-policy-b (author-b)]"));
        });

        assertThat(qm.getNotificationOutbox())
                .filteredOn(notification -> notification.getGroup() == GROUP_PROJECT_AUDIT_CHANGE)
                .singleElement()
                .satisfies(notification -> assertThat(notification.getSubject()
                        .unpack(org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject.class)
                        .getAnalysis()
                        .getPolicyAnnotationsList())
                        .extracting(
                                org.dependencytrack.notification.proto.v1.AppliedPolicyAnnotation::getPolicyName,
                                org.dependencytrack.notification.proto.v1.AppliedPolicyAnnotation::getAnnotator)
                        .containsExactlyInAnyOrder(
                                tuple("gem-policy-a", "author-a"),
                                tuple("gem-policy-b", "author-b")));
    }

    @Test
    void analysisThroughPolicyNewAnalysisSuppressionTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-101");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.CRITICAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.FALSE_POSITIVE);
        policyAnalysis.setSuppress(true);

        final var cvssV4Rating = new VulnerabilityPolicyRating();
        cvssV4Rating.setMethod(VulnerabilityPolicyRating.Method.CVSSV4);
        cvssV4Rating.setVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
        cvssV4Rating.setScore(0.0);
        cvssV4Rating.setSeverity(VulnerabilityPolicyRating.Severity.LOW);

        createPolicy("suppressPolicy", "testAuthor",
                "true",
                policyAnalysis, List.of(cvssV4Rating));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.FALSE_POSITIVE);
            assertThat(analysis.isSuppressed()).isTrue();
            assertThat(analysis.getSeverity()).isEqualTo(Severity.LOW);
            assertThat(analysis.getCvssV4Vector()).isEqualTo("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N");
            assertThat(analysis.getCvssV4Score()).isEqualByComparingTo("0.0");
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactly(
                            "Matched on condition: true",
                            "Analysis: NOT_SET → FALSE_POSITIVE",
                            "Suppressed",
                            "Severity: UNASSIGNED → LOW",
                            "CVSSv4 Vector: (None) → CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
                            "CVSSv4 Score: (None) → 0.0");
        });

        // Suppressed finding should NOT generate a NEW_VULNERABILITY notification,
        // but should still generate a PROJECT_AUDIT_CHANGE notification.
        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification ->
                assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE));
    }

    @Test
    void analysisThroughPolicyExistingDifferentAnalysisTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-102");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.CRITICAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        qm.addVulnerability(vuln, component, "internal");

        // Pre-create analysis with different values than the policy will set.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.IN_TRIAGE)
                        .withJustification(AnalysisJustification.NOT_SET)
                        .withResponse(AnalysisResponse.NOT_SET)
                        .withDetails("old details")
                        .withSuppress(false)
                        .withOptions(Set.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        policyAnalysis.setJustification(VulnerabilityPolicyAnalysis.Justification.CODE_NOT_REACHABLE);
        policyAnalysis.setVendorResponse(VulnerabilityPolicyAnalysis.Response.WILL_NOT_FIX);
        policyAnalysis.setDetails("new details");
        policyAnalysis.setSuppress(true);

        final var cvssV3Rating = new VulnerabilityPolicyRating();
        cvssV3Rating.setMethod(VulnerabilityPolicyRating.Method.CVSSV3);
        cvssV3Rating.setVector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
        cvssV3Rating.setScore(3.7);
        cvssV3Rating.setSeverity(VulnerabilityPolicyRating.Severity.LOW);

        createPolicy("updatePolicy", "testAuthor",
                "has(component.name)",
                policyAnalysis, List.of(cvssV3Rating));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(analysis.getAnalysisJustification()).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE);
            assertThat(analysis.getAnalysisResponse()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
            assertThat(analysis.getAnalysisDetails()).isEqualTo("new details");
            assertThat(analysis.isSuppressed()).isTrue();
            assertThat(analysis.getSeverity()).isEqualTo(Severity.LOW);
            assertThat(analysis.getCvssV3Vector()).isEqualTo("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
            assertThat(analysis.getCvssV3Score()).isEqualByComparingTo("3.7");
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactly(
                            "Matched on condition: has(component.name)",
                            "Analysis: IN_TRIAGE → NOT_AFFECTED",
                            "Justification: NOT_SET → CODE_NOT_REACHABLE",
                            "Vendor Response: NOT_SET → WILL_NOT_FIX",
                            "Details: new details",
                            "Suppressed",
                            "Severity: UNASSIGNED → LOW",
                            "CVSSv3 Vector: (None) → CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
                            "CVSSv3 Score: (None) → 3.7");
        });

        // Existing finding should not trigger NEW_VULNERABILITY notification,
        // but state and suppression changed, so PROJECT_AUDIT_CHANGE should be emitted.
        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification ->
                assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE));
    }

    @Test
    void analysisThroughPolicyExistingEqualAnalysisTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-103");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        qm.addVulnerability(vuln, component, "internal");

        // Pre-create analysis with values that exactly match the policy.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withSuppress(false)
                        .withOptions(Set.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);

        createPolicy("matchingPolicy", "testAuthor",
                "true",
                policyAnalysis, null);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(analysis.getAnalysisComments()).isEmpty();
        });
    }

    @Test
    void analysisThroughPolicyWithPoliciesNotYetValidOrNotValidAnymoreTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-104");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        // Policy with validFrom in the future.
        final var futureAnalysis = new VulnerabilityPolicyAnalysis();
        futureAnalysis.setState(VulnerabilityPolicyAnalysis.State.FALSE_POSITIVE);

        final var futurePolicy = new VulnerabilityPolicy();
        futurePolicy.setName("futurePolicy");
        futurePolicy.setCondition("true");
        futurePolicy.setAnalysis(futureAnalysis);
        futurePolicy.setValidFrom(ZonedDateTime.now().plusDays(30));
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(futurePolicy));

        // Policy with validUntil in the past.
        final var expiredAnalysis = new VulnerabilityPolicyAnalysis();
        expiredAnalysis.setState(VulnerabilityPolicyAnalysis.State.RESOLVED);

        final var expiredPolicy = new VulnerabilityPolicy();
        expiredPolicy.setName("expiredPolicy");
        expiredPolicy.setCondition("true");
        expiredPolicy.setAnalysis(expiredAnalysis);
        expiredPolicy.setValidUntil(ZonedDateTime.now().minusDays(30));
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(expiredPolicy));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).isNull();
    }

    @Test
    void analysisThroughPolicyWithAnalysisUpdateNotOnStateOrSuppressionTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-105");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        qm.addVulnerability(vuln, component, "internal");

        // Pre-create analysis with same state/suppressed as policy but different details.
        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withDetails("old details")
                        .withSuppress(false)
                        .withOptions(Set.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
        policyAnalysis.setDetails("new details");

        createPolicy("detailsPolicy", "testAuthor",
                "true",
                policyAnalysis, null);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).satisfies(analysis -> {
            assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(analysis.getAnalysisDetails()).isEqualTo("new details");
            assertThat(analysis.isSuppressed()).isFalse();
            assertThat(analysis.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactly(
                            "Matched on condition: true",
                            "Details: new details");
        });

        // No state or suppression change, so no NEW_VULNERABILITY or PROJECT_AUDIT_CHANGE.
        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void analysisThroughPolicyWithPoliciesLoggableTest() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INT-106");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln = qm.persist(vuln);

        final var vs = new VulnerableSoftware();
        vs.setPurlType("maven");
        vs.setPurlNamespace("com.example");
        vs.setPurlName("acme-lib");
        vs.setVersionStartIncluding("1.0.0");
        vs.setVersionEndExcluding("2.0.0");
        vs.setVulnerable(true);
        vs.addVulnerability(vuln);
        qm.persist(vs);

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        qm.persist(component);

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.FALSE_POSITIVE);

        final var policy = new VulnerabilityPolicy();
        policy.setName("logPolicy");
        policy.setCondition("true");
        policy.setAnalysis(policyAnalysis);
        policy.setOperationMode(VulnerabilityPolicyOperation.LOG);
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(policy));

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();
        assertThat(qm.getAnalysis(component, vuln)).isNull();
    }

    @Test
    void analysisThroughPolicyResetOnNoMatchTest() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setGroup("com.example");
        component.setName("acme-lib");
        component.setVersion("1.1.0");
        component.setPurl("pkg:maven/com.example/acme-lib@1.1.0");
        component.setProject(project);
        qm.persist(component);

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.FALSE_POSITIVE);
        policyAnalysis.setJustification(VulnerabilityPolicyAnalysis.Justification.CODE_NOT_REACHABLE);
        policyAnalysis.setVendorResponse(VulnerabilityPolicyAnalysis.Response.WILL_NOT_FIX);
        policyAnalysis.setSuppress(true);
        final var policy = new VulnerabilityPolicy();
        policy.setName("Foo");
        policy.setCondition("component.name == \"some-other-name\"");
        policy.setAnalysis(policyAnalysis);
        policy.setOperationMode(VulnerabilityPolicyOperation.APPLY);
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(policy));

        // Create vulnerability with existing analysis that was previously applied by the above policy,
        // but is no longer current.
        final var vulnA = new Vulnerability();
        vulnA.setVulnId("CVE-100");
        vulnA.setSource(Vulnerability.Source.NVD);
        vulnA.setSeverity(Severity.CRITICAL);
        qm.persist(vulnA);
        qm.addVulnerability(vulnA, component, "internal");
        final var analysisA = new Analysis();
        analysisA.setComponent(component);
        analysisA.setVulnerability(vulnA);
        analysisA.setAnalysisState(AnalysisState.NOT_AFFECTED);
        analysisA.setAnalysisJustification(AnalysisJustification.CODE_NOT_REACHABLE);
        analysisA.setAnalysisResponse(AnalysisResponse.WILL_NOT_FIX);
        analysisA.setAnalysisDetails("Because I say so.");
        analysisA.setSeverity(Severity.MEDIUM);
        analysisA.setCvssV2Vector("oldCvssV2Vector");
        analysisA.setCvssV2Score(BigDecimal.valueOf(1.1));
        analysisA.setCvssV3Vector("oldCvssV3Vector");
        analysisA.setCvssV3Score(BigDecimal.valueOf(2.2));
        analysisA.setOwaspVector("oldOwaspVector");
        analysisA.setOwaspScore(BigDecimal.valueOf(3.3));
        analysisA.setCvssV4Vector("oldCvssV4Vector");
        analysisA.setCvssV4Score(BigDecimal.valueOf(4.4));
        analysisA.setSuppressed(true);
        analysisA.setPolicyAnnotations(List.of(
                new AppliedPolicyAnnotation("Foo", Instant.parse("2020-01-01T00:00:00Z"), "author")));
        qm.persist(analysisA);
        useJdbiHandle(jdbiHandle -> jdbiHandle.createUpdate("""
                        UPDATE
                          "ANALYSIS"
                        SET
                          "VULNERABILITY_POLICY_ID" = (SELECT "ID" FROM "VULNERABILITY_POLICY" WHERE "NAME" = :vulnPolicyName)
                        WHERE
                          "ID" = :analysisId
                        """)
                .bind("vulnPolicyName", policy.getName())
                .bind("analysisId", analysisA.getId())
                .execute());

        // Create another vulnerability with existing analysis that was manually applied.
        final var vulnB = new Vulnerability();
        vulnB.setVulnId("CVE-200");
        vulnB.setSource(Vulnerability.Source.NVD);
        vulnB.setSeverity(Severity.HIGH);
        qm.persist(vulnB);
        qm.addVulnerability(vulnB, component, "internal");
        final var analysisB = new Analysis();
        analysisB.setComponent(component);
        analysisB.setVulnerability(vulnB);
        analysisB.setAnalysisState(AnalysisState.NOT_AFFECTED);
        qm.persist(analysisB);

        // Ensure that CVE-100 and CVE-200 will still be reported.
        final var vsVulnA = new VulnerableSoftware();
        vsVulnA.setPurlType("maven");
        vsVulnA.setPurlNamespace("com.example");
        vsVulnA.setPurlName("acme-lib");
        vsVulnA.setVersionStartIncluding("1.0.0");
        vsVulnA.setVersionEndExcluding("2.0.0");
        vsVulnA.setVulnerable(true);
        vsVulnA.addVulnerability(vulnA);
        qm.persist(vsVulnA);
        final var vsB = new VulnerableSoftware();
        vsB.setPurlType("maven");
        vsB.setPurlNamespace("com.example");
        vsB.setPurlName("acme-lib");
        vsB.setVersionStartIncluding("1.0.0");
        vsB.setVersionEndExcluding("2.0.0");
        vsB.setVulnerable(true);
        vsB.addVulnerability(vulnB);
        qm.persist(vsB);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        qm.getPersistenceManager().evictAll();

        // The analysis that was previously applied via policy must have been reverted.
        assertThat(qm.getAnalysis(component, vulnA)).satisfies(a -> {
            assertThat(a.getAnalysisState()).isEqualTo(AnalysisState.NOT_SET);
            assertThat(a.getVulnerabilityPolicyId()).isNull();
            assertThat(a.isSuppressed()).isFalse();
            assertThat(a.getPolicyAnnotations()).isNull();
            assertThat(a.getAnalysisComments())
                    .extracting(AnalysisComment::getCommenter)
                    .containsOnly("Policy");
            assertThat(a.getAnalysisComments())
                    .extracting(AnalysisComment::getComment)
                    .containsExactlyInAnyOrder(
                            "No longer covered by any policy",
                            "Analysis: NOT_AFFECTED → NOT_SET",
                            "Justification: CODE_NOT_REACHABLE → NOT_SET",
                            "Vendor Response: WILL_NOT_FIX → NOT_SET",
                            "Details: (None)",
                            "Severity: MEDIUM → UNASSIGNED",
                            "CVSSv2 Vector: oldCvssV2Vector → (None)",
                            "CVSSv2 Score: 1.1 → (None)",
                            "CVSSv3 Vector: oldCvssV3Vector → (None)",
                            "CVSSv3 Score: 2.2 → (None)",
                            "OWASP Vector: oldOwaspVector → (None)",
                            "OWASP Score: 3.3 → (None)",
                            "CVSSv4 Vector: oldCvssV4Vector → (None)",
                            "CVSSv4 Score: 4.4 → (None)",
                            "Unsuppressed",
                            "Policy annotations: [Foo (author)] → (None)");
        });

        // The manually applied analysis must not be touched.
        assertThat(qm.getAnalysis(component, vulnB)).satisfies(a -> {
            assertThat(a.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(a.getVulnerabilityPolicyId()).isNull();
            assertThat(a.getAnalysisComments()).isEmpty();
        });
    }

    @Test
    void shouldFailWhenAllAnalyzersFailed() {
        pluginManager
                .getMutableConfigRegistry(VulnAnalyzer.class, "internal")
                .setRuntimeConfig(
                        new InternalVulnAnalyzerConfigV1()
                                .withEnabled(false));

        mockAnalyzerFunction.set(bom -> null);

        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl("pkg:maven/com.example/acme-lib@1.0.0");
        qm.persist(component);

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.FAILED);

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getLastVulnerabilityAnalysis()).isNull();
    }

    @Test
    void shouldSyncVulnAndAliasAssertionsFromExternalAnalyzer() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.9.8");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8");
        qm.persist(component);

        mockAnalyzerFunction.set(bom -> Bom.newBuilder()
                .addVulnerabilities(
                        org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                                .setId("CVE-2024-1234")
                                .setSource(Source.newBuilder().setName("NVD"))
                                .addAffects(VulnerabilityAffects.newBuilder().setRef(bom.getComponents(0).getBomRef()))
                                .addReferences(VulnerabilityReference.newBuilder()
                                        .setId("GHSA-xxxx-xxxx-xxxx")
                                        .setSource(Source.newBuilder().setName("GITHUB"))))
                .build());

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(qm.getVulnerabilities(project, true))
                .extracting(Vulnerability::getVulnId)
                .containsExactly("CVE-2024-1234");

        final long projectId = project.getId();
        final List<FindingDao.FindingRow> findings = withJdbiHandle(
                handle -> handle.attach(FindingDao.class)
                        .getFindingsByProject(
                                projectId,
                                /* includeInactive */ false,
                                /* includeSuppressed */ false,
                                /* searchText */ null,
                                /* hasAnalysis */ null,
                                /* source */ null,
                                /* epssFrom */ null,
                                /* epssTo */ null));
        assertThat(findings).hasSize(1);

        assertThat(getAllAliasGroups()).satisfiesExactly(group ->
                assertThat(group).containsExactlyInAnyOrder(
                        new VulnerabilityKey("CVE-2024-1234", "NVD"),
                        new VulnerabilityKey("GHSA-xxxx-xxxx-xxxx", "GITHUB")));
    }

    @Test
    void shouldRemoveStaleAliasAssertionsWhenAnalyzerNoLongerReportsThem() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.9.8");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8");
        qm.persist(component);

        mockAnalyzerFunction.set(bom -> Bom.newBuilder()
                .addVulnerabilities(
                        org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                                .setId("CVE-2024-1234")
                                .setSource(Source.newBuilder().setName("NVD"))
                                .addAffects(VulnerabilityAffects.newBuilder().setRef(bom.getComponents(0).getBomRef()))
                                .addReferences(VulnerabilityReference.newBuilder()
                                        .setId("GHSA-xxxx-xxxx-xxxx")
                                        .setSource(Source.newBuilder().setName("GITHUB"))))
                .build());

        UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(getAllAliasGroups()).hasSize(1);

        mockAnalyzerFunction.set(bom -> Bom.newBuilder()
                .addVulnerabilities(
                        org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                                .setId("CVE-2024-1234")
                                .setSource(Source.newBuilder().setName("NVD"))
                                .addAffects(VulnerabilityAffects.newBuilder().setRef(bom.getComponents(0).getBomRef())))
                .build());

        runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(getAllAliasGroups()).isEmpty();
    }

    @Test
    void shouldHandleUnknownVulnSourceAndSkipAliasAssertions() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("com.fasterxml.jackson.core");
        component.setName("jackson-databind");
        component.setVersion("2.9.8");
        component.setPurl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8");
        qm.persist(component);

        mockAnalyzerFunction.set(bom -> Bom.newBuilder()
                .addVulnerabilities(
                        org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                                .setId("FOO-1")
                                .setSource(Source.newBuilder().setName("FOO"))
                                .addAffects(VulnerabilityAffects.newBuilder().setRef(bom.getComponents(0).getBomRef()))
                                .addReferences(VulnerabilityReference.newBuilder()
                                        .setId("GHSA-aaaa-aaaa-aaaa")
                                        .setSource(Source.newBuilder().setName("GITHUB"))))
                .addVulnerabilities(
                        org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                                .setId("CVE-2024-9999")
                                .setSource(Source.newBuilder().setName("NVD"))
                                .addAffects(VulnerabilityAffects.newBuilder().setRef(bom.getComponents(0).getBomRef()))
                                .addReferences(VulnerabilityReference.newBuilder()
                                        .setId("FOO-9")
                                        .setSource(Source.newBuilder().setName("FOO")))
                                .addReferences(VulnerabilityReference.newBuilder()
                                        .setId("GHSA-bbbb-bbbb-bbbb")
                                        .setSource(Source.newBuilder().setName("GITHUB"))))
                .build());

        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(VulnAnalysisWorkflow.class)
                        .withArgument(VulnAnalysisWorkflowArg.newBuilder()
                                .setProjectUuid(project.getUuid().toString())
                                .build()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(qm.getVulnerabilities(project, true))
                .extracting(Vulnerability::getVulnId, Vulnerability::getSource)
                .containsExactlyInAnyOrder(
                        tuple("FOO-1", Vulnerability.Source.UNKNOWN.name()),
                        tuple("CVE-2024-9999", Vulnerability.Source.NVD.name()));

        assertThat(getAllAliasGroups()).satisfiesExactly(group ->
                assertThat(group).containsExactlyInAnyOrder(
                        new VulnerabilityKey("CVE-2024-9999", "NVD"),
                        new VulnerabilityKey("GHSA-bbbb-bbbb-bbbb", "GITHUB")));
    }

    private record AliasRow(UUID groupId, String source, String vulnId) {
    }

    private List<Set<VulnerabilityKey>> getAllAliasGroups() {
        return withJdbiHandle(handle -> handle
                .createQuery("""
                        SELECT "GROUP_ID"
                             , "SOURCE"
                             , "VULN_ID"
                          FROM "VULNERABILITY_ALIAS"
                        """)
                .map((rs, _) -> new AliasRow(
                        rs.getObject("group_id", UUID.class),
                        rs.getString("source"),
                        rs.getString("vuln_id")))
                .list()
                .stream()
                .collect(Collectors.groupingBy(AliasRow::groupId))
                .values()
                .stream()
                .map(rows -> rows.stream()
                        .map(row -> new VulnerabilityKey(row.vulnId(), row.source()))
                        .collect(Collectors.toUnmodifiableSet()))
                .toList());
    }

    private static void createPolicy(
            String name,
            String author,
            String condition,
            VulnerabilityPolicyAnalysis analysis,
            List<VulnerabilityPolicyRating> ratings) {
        final var policy = new VulnerabilityPolicy();
        policy.setName(name);
        policy.setAuthor(author);
        policy.setCondition(condition);
        policy.setAnalysis(analysis);
        policy.setRatings(ratings);
        withJdbiHandle(handle -> handle.attach(VulnerabilityPolicyDao.class).create(policy));
    }

}
