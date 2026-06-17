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
package org.dependencytrack.metrics;

import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.dependencytrack.proto.internal.workflow.v1.FetchProjectMetricsUpdateCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class UpdatePortfolioMetricsWorkflowTest extends AbstractMetricsUpdateTaskTest {

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    @BeforeEach
    void beforeEach() {
        createTestConfigProperties();

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new UpdatePortfolioMetricsWorkflow(),
                voidConverter(),
                voidConverter(),
                Duration.ofSeconds(30));
        engine.registerActivity(
                new FetchProjectMetricsUpdateCandidatesActivity(),
                voidConverter(),
                protoConverter(FetchProjectMetricsUpdateCandidatesRes.class),
                Duration.ofSeconds(10));
        engine.registerActivity(
                new RefreshGlobalPortfolioMetricsActivity(),
                voidConverter(),
                voidConverter(),
                Duration.ofSeconds(10));
        engine.registerActivity(
                new UpdateProjectMetricsActivity(),
                protoConverter(UpdateProjectMetricsArg.class),
                voidConverter(),
                Duration.ofSeconds(10));

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "metrics-updates", 5));

        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-metrics", "metrics-updates", 5)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    private UUID runWorkflow() {
        final UUID runId = workflowTest.getEngine().createRun(
                new CreateWorkflowRunRequest<>(UpdatePortfolioMetricsWorkflow.class));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);
        return runId;
    }

    @Test
    void shouldUpdateMetricsEmpty() {
        runWorkflow();

        final PortfolioMetrics metrics = withJdbiHandle(
                handle -> handle.attach(MetricsDao.class).getMostRecentPortfolioMetrics());
        assertThat(metrics.getProjects()).isZero();
        assertThat(metrics.getVulnerableProjects()).isZero();
        assertThat(metrics.getComponents()).isZero();
        assertThat(metrics.getVulnerableComponents()).isZero();
        assertThat(metrics.getCritical()).isZero();
        assertThat(metrics.getHigh()).isZero();
        assertThat(metrics.getMedium()).isZero();
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isZero();
        assertThat(metrics.getVulnerabilities()).isZero();
        assertThat(metrics.getSuppressed()).isZero();
        assertThat(metrics.getFindingsTotal()).isZero();
        assertThat(metrics.getFindingsAudited()).isZero();
        assertThat(metrics.getFindingsUnaudited()).isZero();
        assertThat(metrics.getInheritedRiskScore()).isZero();
        assertThat(metrics.getPolicyViolationsFail()).isZero();
        assertThat(metrics.getPolicyViolationsWarn()).isZero();
        assertThat(metrics.getPolicyViolationsInfo()).isZero();
        assertThat(metrics.getPolicyViolationsTotal()).isZero();
        assertThat(metrics.getPolicyViolationsAudited()).isZero();
        assertThat(metrics.getPolicyViolationsUnaudited()).isZero();
        assertThat(metrics.getPolicyViolationsSecurityTotal()).isZero();
        assertThat(metrics.getPolicyViolationsSecurityAudited()).isZero();
        assertThat(metrics.getPolicyViolationsSecurityUnaudited()).isZero();
        assertThat(metrics.getPolicyViolationsLicenseTotal()).isZero();
        assertThat(metrics.getPolicyViolationsLicenseAudited()).isZero();
        assertThat(metrics.getPolicyViolationsLicenseUnaudited()).isZero();
        assertThat(metrics.getPolicyViolationsOperationalTotal()).isZero();
        assertThat(metrics.getPolicyViolationsOperationalAudited()).isZero();
        assertThat(metrics.getPolicyViolationsOperationalUnaudited()).isZero();
    }

    @Test
    void shouldUpdateMetricsVulnerabilities() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln);

        // Create a project with an unaudited vulnerability.
        var projectUnaudited = new Project();
        projectUnaudited.setName("acme-app-a");
        qm.createProject(projectUnaudited, List.of(), false);

        var componentUnaudited = new Component();
        componentUnaudited.setProject(projectUnaudited);
        componentUnaudited.setName("acme-lib-a");
        qm.createComponent(componentUnaudited, false);
        qm.addVulnerability(vuln, componentUnaudited, "none");

        // Create a project with an audited vulnerability.
        var projectAudited = new Project();
        projectAudited.setName("acme-app-b");
        qm.createProject(projectAudited, List.of(), false);

        var componentAudited = new Component();
        componentAudited.setProject(projectAudited);
        componentAudited.setName("acme-lib-b");
        qm.createComponent(componentAudited, false);
        qm.addVulnerability(vuln, componentAudited, "none");
        qm.makeAnalysis(
                new MakeAnalysisCommand(componentAudited, vuln)
                        .withState(AnalysisState.NOT_AFFECTED));

        // Create a project with a suppressed vulnerability.
        var projectSuppressed = new Project();
        projectSuppressed.setName("acme-app-c");
        qm.createProject(projectSuppressed, List.of(), false);

        var componentSuppressed = new Component();
        componentSuppressed.setProject(projectSuppressed);
        componentSuppressed.setName("acme-lib-c");
        qm.createComponent(componentSuppressed, false);
        qm.addVulnerability(vuln, componentSuppressed, "none");
        qm.makeAnalysis(
                new MakeAnalysisCommand(componentSuppressed, vuln)
                        .withState(AnalysisState.FALSE_POSITIVE)
                        .withSuppress(true));

        runWorkflow();

        final PortfolioMetrics metrics = withJdbiHandle(
                handle -> handle.attach(MetricsDao.class).getMostRecentPortfolioMetrics());
        assertThat(metrics.getProjects()).isEqualTo(3);
        assertThat(metrics.getVulnerableProjects()).isEqualTo(2); // Finding for one project is suppressed
        assertThat(metrics.getComponents()).isEqualTo(3);
        assertThat(metrics.getVulnerableComponents()).isEqualTo(2); // Finding for one component is suppressed
        assertThat(metrics.getCritical()).isZero();
        assertThat(metrics.getHigh()).isEqualTo(2); // One is suppressed
        assertThat(metrics.getMedium()).isZero();
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isZero();
        assertThat(metrics.getVulnerabilities()).isEqualTo(2); // One is suppressed
        assertThat(metrics.getSuppressed()).isEqualTo(1);
        assertThat(metrics.getFindingsTotal()).isEqualTo(2); // One is suppressed
        assertThat(metrics.getFindingsAudited()).isEqualTo(1);
        assertThat(metrics.getFindingsUnaudited()).isEqualTo(1);
        assertThat(metrics.getInheritedRiskScore()).isEqualTo(10.0);
        assertThat(metrics.getPolicyViolationsFail()).isZero();
        assertThat(metrics.getPolicyViolationsWarn()).isZero();
        assertThat(metrics.getPolicyViolationsInfo()).isZero();
        assertThat(metrics.getPolicyViolationsTotal()).isZero();
        assertThat(metrics.getPolicyViolationsAudited()).isZero();
        assertThat(metrics.getPolicyViolationsUnaudited()).isZero();
        assertThat(metrics.getPolicyViolationsSecurityTotal()).isZero();
        assertThat(metrics.getPolicyViolationsSecurityAudited()).isZero();
        assertThat(metrics.getPolicyViolationsSecurityUnaudited()).isZero();
        assertThat(metrics.getPolicyViolationsLicenseTotal()).isZero();
        assertThat(metrics.getPolicyViolationsLicenseAudited()).isZero();
        assertThat(metrics.getPolicyViolationsLicenseUnaudited()).isZero();
        assertThat(metrics.getPolicyViolationsOperationalTotal()).isZero();
        assertThat(metrics.getPolicyViolationsOperationalAudited()).isZero();
        assertThat(metrics.getPolicyViolationsOperationalUnaudited()).isZero();

        qm.getPersistenceManager().refreshAll(projectUnaudited, projectAudited, projectSuppressed,
                componentUnaudited, componentAudited, componentSuppressed);
        assertThat(projectUnaudited.getLastInheritedRiskScore()).isEqualTo(5.0);
        assertThat(projectAudited.getLastInheritedRiskScore()).isEqualTo(5.0);
        assertThat(projectSuppressed.getLastInheritedRiskScore()).isZero();
        assertThat(componentUnaudited.getLastInheritedRiskScore()).isEqualTo(5.0);
        assertThat(componentAudited.getLastInheritedRiskScore()).isEqualTo(5.0);
        assertThat(componentSuppressed.getLastInheritedRiskScore()).isZero();
    }

    @Test
    void shouldUpdateMetricsPolicyViolations() {
        var projectUnaudited = new Project();
        projectUnaudited.setName("acme-app-a");
        qm.createProject(projectUnaudited, List.of(), false);

        var componentUnaudited = new Component();
        componentUnaudited.setProject(projectUnaudited);
        componentUnaudited.setName("acme-lib-a");
        qm.createComponent(componentUnaudited, false);
        createPolicyViolation(componentUnaudited, Policy.ViolationState.FAIL, PolicyViolation.Type.LICENSE);

        // Create a project with an audited violation.
        var projectAudited = new Project();
        projectAudited.setName("acme-app-b");
        qm.createProject(projectAudited, List.of(), false);

        var componentAudited = new Component();
        componentAudited.setProject(projectAudited);
        componentAudited.setName("acme-lib-b");
        qm.createComponent(componentAudited, false);
        final var violationAudited = createPolicyViolation(componentAudited, Policy.ViolationState.WARN, PolicyViolation.Type.OPERATIONAL);
        qm.makeViolationAnalysis(
                new MakeViolationAnalysisCommand(componentAudited, violationAudited)
                        .withState(ViolationAnalysisState.APPROVED));

        // Create a project with a suppressed violation.
        var projectSuppressed = new Project();
        projectSuppressed.setName("acme-app-c");
        qm.createProject(projectSuppressed, List.of(), false);

        var componentSuppressed = new Component();
        componentSuppressed.setProject(projectSuppressed);
        componentSuppressed.setName("acme-lib-c");
        qm.createComponent(componentSuppressed, false);
        final var violationSuppressed = createPolicyViolation(componentSuppressed, Policy.ViolationState.INFO, PolicyViolation.Type.SECURITY);
        qm.makeViolationAnalysis(
                new MakeViolationAnalysisCommand(componentSuppressed, violationSuppressed)
                        .withState(ViolationAnalysisState.REJECTED)
                        .withSuppress(true));

        runWorkflow();

        final PortfolioMetrics metrics = withJdbiHandle(
                handle -> handle.attach(MetricsDao.class).getMostRecentPortfolioMetrics());
        assertThat(metrics.getProjects()).isEqualTo(3);
        assertThat(metrics.getVulnerableProjects()).isZero();
        assertThat(metrics.getComponents()).isEqualTo(3);
        assertThat(metrics.getVulnerableComponents()).isZero();
        assertThat(metrics.getCritical()).isZero();
        assertThat(metrics.getHigh()).isZero();
        assertThat(metrics.getMedium()).isZero();
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isZero();
        assertThat(metrics.getVulnerabilities()).isZero();
        assertThat(metrics.getSuppressed()).isZero();
        assertThat(metrics.getFindingsTotal()).isZero();
        assertThat(metrics.getFindingsAudited()).isZero();
        assertThat(metrics.getFindingsUnaudited()).isZero();
        assertThat(metrics.getInheritedRiskScore()).isZero();
        assertThat(metrics.getPolicyViolationsFail()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsWarn()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsInfo()).isZero(); // Suppressed
        assertThat(metrics.getPolicyViolationsTotal()).isEqualTo(2);
        assertThat(metrics.getPolicyViolationsAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsUnaudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsSecurityTotal()).isZero(); // Suppressed
        assertThat(metrics.getPolicyViolationsSecurityAudited()).isZero();
        assertThat(metrics.getPolicyViolationsSecurityUnaudited()).isZero();
        assertThat(metrics.getPolicyViolationsLicenseTotal()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsLicenseAudited()).isZero();
        assertThat(metrics.getPolicyViolationsLicenseUnaudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsOperationalTotal()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsOperationalAudited()).isEqualTo(1);
        assertThat(metrics.getPolicyViolationsOperationalUnaudited()).isZero();

        qm.getPersistenceManager().refreshAll(projectUnaudited, projectAudited, projectSuppressed,
                componentUnaudited, componentAudited, componentSuppressed);
        assertThat(projectUnaudited.getLastInheritedRiskScore()).isZero();
        assertThat(projectAudited.getLastInheritedRiskScore()).isZero();
        assertThat(projectSuppressed.getLastInheritedRiskScore()).isZero();
        assertThat(componentUnaudited.getLastInheritedRiskScore()).isZero();
        assertThat(componentAudited.getLastInheritedRiskScore()).isZero();
        assertThat(componentSuppressed.getLastInheritedRiskScore()).isZero();
    }

    @Test
    void shouldSkipProjectsWithRecentMetrics() {
        var projectA = new Project();
        projectA.setName("acme-app-a");
        qm.persist(projectA);
        final var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);

        final var projectB = new Project();
        projectB.setName("acme-app-b");
        qm.persist(projectB);
        final var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);

        final var inactiveProject = new Project();
        inactiveProject.setName("inactive-project");
        inactiveProject.setInactiveSince(new Date());
        qm.persist(inactiveProject);

        // Create a metrics data point for projectA, where it has no components.
        // Despite this difference, we expect no metrics refresh to be performed
        // for it, because a data point for the current day is already present.
        useJdbiTransaction(handle -> {
            final var dao = handle.attach(MetricsTestDao.class);
            final var projectAMetrics = new ProjectMetrics();
            projectAMetrics.setProjectId(projectA.getId());
            projectAMetrics.setComponents(0);
            projectAMetrics.setFirstOccurrence(new Date());
            projectAMetrics.setLastOccurrence(new Date());
            dao.createProjectMetrics(projectAMetrics);
        });

        runWorkflow();

        final List<ProjectMetrics> recentProjectMetrics = withJdbiHandle(
                handle -> handle.attach(MetricsDao.class)
                        .getMostRecentProjectMetrics(
                                List.of(projectA.getId(), projectB.getId(), inactiveProject.getId())));

        assertThat(recentProjectMetrics).satisfiesExactlyInAnyOrder(
                metrics -> {
                    assertThat(metrics.getProjectId()).isEqualTo(projectA.getId());
                    assertThat(metrics.getComponents()).isEqualTo(0); // Old value.
                },
                metrics -> {
                    assertThat(metrics.getProjectId()).isEqualTo(projectB.getId());
                    assertThat(metrics.getComponents()).isEqualTo(1);
                }
                // No metrics for inactiveProject.
        );
    }

    @Test
    public void shouldExcludeCollectionProjectsFromPortfolioMetrics() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln);

        var regularProject = new Project();
        regularProject.setName("acme-app-regular");
        qm.createProject(regularProject, List.of(), false);

        var component = new Component();
        component.setProject(regularProject);
        component.setName("acme-lib");
        qm.createComponent(component, false);
        qm.addVulnerability(vuln, component, "none");

        var collectionProject = new Project();
        collectionProject.setName("acme-collection");
        collectionProject.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.createProject(collectionProject, List.of(), false);

        runWorkflow();

        final PortfolioMetrics metrics = withJdbiHandle(handle ->
                handle.attach(MetricsDao.class).getMostRecentPortfolioMetrics());
        assertThat(metrics.getProjects()).isEqualTo(1);
        assertThat(metrics.getComponents()).isEqualTo(1);
        assertThat(metrics.getHigh()).isEqualTo(1);
    }

}
