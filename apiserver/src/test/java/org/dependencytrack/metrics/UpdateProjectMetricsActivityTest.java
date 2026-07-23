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

import org.dependencytrack.kevdatasource.api.KevAssertion;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.DependencyMetrics;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetrics;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeViolationAnalysisCommand;
import org.dependencytrack.persistence.jdbi.KevDao;
import org.dependencytrack.persistence.jdbi.MetricsDao;
import org.dependencytrack.persistence.jdbi.MetricsTestDao;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class UpdateProjectMetricsActivityTest extends AbstractMetricsUpdateTaskTest {

    private final UpdateProjectMetricsActivity activity = new UpdateProjectMetricsActivity();

    @Test
    void shouldUpdateMetricsEmpty() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        // Create risk score configproperties
        createTestConfigProperties();

        executeActivity(project);

        final ProjectMetrics metrics = withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(metrics.getComponents()).isZero();
        assertThat(metrics.getVulnerableComponents()).isZero();
        assertThat(metrics.getCritical()).isZero();
        assertThat(metrics.getHigh()).isZero();
        assertThat(metrics.getMedium()).isZero();
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isZero();
        assertThat(metrics.getKev()).isZero();
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

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getLastInheritedRiskScore()).isZero();
    }

    @Test
    void shouldNotCreateNewRowsWhenMetricsUnchanged() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib-a");
        qm.createComponent(component, false);

        // Create risk score configproperties
        createTestConfigProperties();

        // Record initial metrics
        executeActivity(project);

        final ProjectMetrics initialProjectMetrics = withJdbiHandle(
                handle -> handle
                        .attach(MetricsDao.class)
                        .getMostRecentProjectMetrics(project.getId()));
        assertThat(initialProjectMetrics.getLastOccurrence())
                .isEqualTo(initialProjectMetrics.getFirstOccurrence());

        // Run the task a second time, without any metric being changed
        executeActivity(project);

        // No new row must have been created, and the existing row's timestamp must remain untouched
        final List<ProjectMetrics> projectMetrics = withJdbiHandle(
                handle -> handle
                        .attach(MetricsDao.class)
                        .getProjectMetricsSince(project.getId(), Instant.EPOCH));
        assertThat(projectMetrics)
                .hasSize(1)
                .first()
                .extracting(ProjectMetrics::getLastOccurrence)
                .isEqualTo(initialProjectMetrics.getLastOccurrence());

        final List<DependencyMetrics> componentMetrics = withJdbiHandle(
                handle -> handle
                        .attach(MetricsDao.class)
                        .getDependencyMetricsSince(component.getId(), Instant.EPOCH));
        assertThat(componentMetrics).hasSize(1);
    }

    @Test
    void shouldCreateNewRowsWhenMetricsChanged() throws Exception {
        createTestConfigProperties();

        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib-a");
        qm.createComponent(component, false);

        // Populate initial metrics.
        executeActivity(project);

        // Make component affected by a vuln so its metrics values
        // will differ from the initial ones.
        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln);
        qm.addVulnerability(vuln, component, "none");

        // Calculate metrics again.
        executeActivity(project);

        // New rows must be created despite snapshots existing for the current day.
        final List<ProjectMetrics> projectMetrics = withJdbiHandle(
                handle -> handle
                        .attach(MetricsDao.class)
                        .getProjectMetricsSince(project.getId(), Instant.EPOCH));
        assertThat(projectMetrics)
                .hasSize(2)
                .last()
                .extracting(ProjectMetrics::getVulnerabilities)
                .isEqualTo(1);

        final List<DependencyMetrics> componentMetrics = withJdbiHandle(
                handle -> handle
                        .attach(MetricsDao.class)
                        .getDependencyMetricsSince(component.getId(), Instant.EPOCH));
        assertThat(componentMetrics)
                .hasSize(2)
                .last()
                .extracting(DependencyMetrics::getVulnerabilities)
                .isEqualTo(1);
    }

    @Test
    void shouldUpdateMetricsVulnerabilities() throws Exception {
        var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        // Create risk score configproperties
        createTestConfigProperties();

        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln);

        useJdbiHandle(handle -> handle
                .attach(KevDao.class)
                .upsertBatch("cisa", List.of(
                        new KevAssertion(
                                "INTERNAL",
                                "INTERNAL-001",
                                null,
                                null,
                                null,
                                null,
                                null))));

        // Create a component with an unaudited vulnerability.
        var componentUnaudited = new Component();
        componentUnaudited.setProject(project);
        componentUnaudited.setName("acme-lib-a");
        qm.createComponent(componentUnaudited, false);
        qm.addVulnerability(vuln, componentUnaudited, "none");

        // Create a component with an audited vulnerability.
        var componentAudited = new Component();
        componentAudited.setProject(project);
        componentAudited.setName("acme-lib-b");
        qm.createComponent(componentAudited, false);
        qm.addVulnerability(vuln, componentAudited, "none");
        qm.makeAnalysis(
                new MakeAnalysisCommand(componentAudited, vuln)
                        .withState(AnalysisState.NOT_AFFECTED));

        // Create a component with a suppressed vulnerability.
        var componentSuppressed = new Component();
        componentSuppressed.setProject(project);
        componentSuppressed.setName("acme-lib-c");
        qm.createComponent(componentSuppressed, false);
        qm.addVulnerability(vuln, componentSuppressed, "none");
        qm.makeAnalysis(
                new MakeAnalysisCommand(componentSuppressed, vuln)
                        .withState(AnalysisState.FALSE_POSITIVE)
                        .withSuppress(true));

        // Create "old" metrics data points for all three components.
        // When calculating project metrics, only the latest data point for each component
        // must be considered. Because the activity calculates new component metrics data points,
        // the ones created below must be ignored.
        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);
            final var componentUnauditedOldMetrics = new DependencyMetrics();
            componentUnauditedOldMetrics.setProjectId(project.getId());
            componentUnauditedOldMetrics.setComponentId(componentUnaudited.getId());
            componentUnauditedOldMetrics.setCritical(666);
            componentUnauditedOldMetrics.setFirstOccurrence(Date.from(Instant.ofEpochSecond(1670843532)));
            componentUnauditedOldMetrics.setLastOccurrence(Date.from(Instant.now()));
            dao.createDependencyMetrics(componentUnauditedOldMetrics);

            final var componentAuditedOldMetrics = new DependencyMetrics();
            componentAuditedOldMetrics.setProjectId(project.getId());
            componentAuditedOldMetrics.setComponentId(componentAudited.getId());
            componentAuditedOldMetrics.setHigh(666);
            componentAuditedOldMetrics.setFirstOccurrence(Date.from(Instant.ofEpochSecond(1670843532)));
            componentAuditedOldMetrics.setLastOccurrence(Date.from(Instant.now()));
            dao.createDependencyMetrics(componentAuditedOldMetrics);

            final var componentSuppressedOldMetrics = new DependencyMetrics();
            componentSuppressedOldMetrics.setProjectId(project.getId());
            componentSuppressedOldMetrics.setComponentId(componentSuppressed.getId());
            componentSuppressedOldMetrics.setMedium(666);
            componentSuppressedOldMetrics.setFirstOccurrence(Date.from(Instant.ofEpochSecond(1670843532)));
            componentSuppressedOldMetrics.setLastOccurrence(Date.from(Instant.now()));
            dao.createDependencyMetrics(componentSuppressedOldMetrics);
        });

        executeActivity(project);

        final ProjectMetrics metrics = withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(metrics.getComponents()).isEqualTo(3);
        assertThat(metrics.getVulnerableComponents()).isEqualTo(2); // Finding for one component is suppressed
        assertThat(metrics.getCritical()).isZero();
        assertThat(metrics.getHigh()).isEqualTo(2); // One is suppressed
        assertThat(metrics.getMedium()).isZero();
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isZero();
        assertThat(metrics.getKev()).isEqualTo(2); // One is suppressed
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

        qm.getPersistenceManager().refreshAll(project, componentUnaudited, componentAudited, componentSuppressed);
        assertThat(project.getLastInheritedRiskScore()).isEqualTo(10.0);
        assertThat(componentUnaudited.getLastInheritedRiskScore()).isEqualTo(5.0);
        assertThat(componentAudited.getLastInheritedRiskScore()).isEqualTo(5.0);
        assertThat(componentSuppressed.getLastInheritedRiskScore()).isZero();
    }

    @Test
    void shouldUpdateMetricsPolicyViolations() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        // Create risk score configproperties
        createTestConfigProperties();

        // Create a component with an unaudited violation.
        var componentUnaudited = new Component();
        componentUnaudited.setProject(project);
        componentUnaudited.setName("acme-lib-a");
        qm.createComponent(componentUnaudited, false);
        createPolicyViolation(componentUnaudited, Policy.ViolationState.FAIL, PolicyViolation.Type.LICENSE);

        // Create a component with an audited violation.
        var componentAudited = new Component();
        componentAudited.setProject(project);
        componentAudited.setName("acme-lib-b");
        qm.createComponent(componentAudited, false);
        final var violationAudited = createPolicyViolation(componentAudited, Policy.ViolationState.WARN, PolicyViolation.Type.OPERATIONAL);
        qm.makeViolationAnalysis(
                new MakeViolationAnalysisCommand(componentAudited, violationAudited)
                        .withState(ViolationAnalysisState.APPROVED));

        // Create a component with a suppressed violation.
        var componentSuppressed = new Component();
        componentSuppressed.setProject(project);
        componentSuppressed.setName("acme-lib-c");
        qm.createComponent(componentSuppressed, false);
        final var violationSuppressed = createPolicyViolation(componentSuppressed, Policy.ViolationState.INFO, PolicyViolation.Type.SECURITY);
        qm.makeViolationAnalysis(
                new MakeViolationAnalysisCommand(componentSuppressed, violationSuppressed)
                        .withState(ViolationAnalysisState.REJECTED)
                        .withSuppress(true));

        // Create "old" metrics data points for all three components.
        // When calculating project metrics, only the latest data point for each component
        // must be considered. Because the activity calculates new component metrics data points,
        // the ones created below must be ignored.
        useJdbiHandle(handle -> {
            var dao = handle.attach(MetricsTestDao.class);
            final var componentUnauditedOldMetrics = new DependencyMetrics();
            componentUnauditedOldMetrics.setProjectId(project.getId());
            componentUnauditedOldMetrics.setComponentId(componentUnaudited.getId());
            componentUnauditedOldMetrics.setPolicyViolationsFail(666);
            componentUnauditedOldMetrics.setFirstOccurrence(Date.from(Instant.ofEpochSecond(1670843532)));
            componentUnauditedOldMetrics.setLastOccurrence(Date.from(Instant.now()));
            dao.createDependencyMetrics(componentUnauditedOldMetrics);

            final var componentAuditedOldMetrics = new DependencyMetrics();
            componentAuditedOldMetrics.setProjectId(project.getId());
            componentAuditedOldMetrics.setComponentId(componentAudited.getId());
            componentAuditedOldMetrics.setHigh(666);
            componentAuditedOldMetrics.setFirstOccurrence(Date.from(Instant.ofEpochSecond(1670843532)));
            componentAuditedOldMetrics.setLastOccurrence(Date.from(Instant.now()));
            dao.createDependencyMetrics(componentAuditedOldMetrics);

            final var componentSuppressedOldMetrics = new DependencyMetrics();
            componentSuppressedOldMetrics.setProjectId(project.getId());
            componentSuppressedOldMetrics.setComponentId(componentSuppressed.getId());
            componentSuppressedOldMetrics.setMedium(666);
            componentSuppressedOldMetrics.setFirstOccurrence(Date.from(Instant.ofEpochSecond(1670843532)));
            componentSuppressedOldMetrics.setLastOccurrence(Date.from(Instant.now()));
            dao.createDependencyMetrics(componentSuppressedOldMetrics);
        });

        executeActivity(project);

        final ProjectMetrics metrics = withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(metrics.getComponents()).isEqualTo(3);
        assertThat(metrics.getVulnerableComponents()).isZero();
        assertThat(metrics.getCritical()).isZero();
        assertThat(metrics.getHigh()).isZero();
        assertThat(metrics.getMedium()).isZero();
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isZero();
        assertThat(metrics.getKev()).isZero();
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

        qm.getPersistenceManager().refreshAll(project, componentUnaudited, componentAudited, componentSuppressed);
        assertThat(project.getLastInheritedRiskScore()).isZero();
        assertThat(componentUnaudited.getLastInheritedRiskScore()).isZero();
        assertThat(componentAudited.getLastInheritedRiskScore()).isZero();
        assertThat(componentSuppressed.getLastInheritedRiskScore()).isZero();
    }

    @Test
    void shouldComputeSameMetricsAsComponentLevelComputation() throws Exception {
        // NB: Project metrics calculate metrics of all components within the project
        // in bulk. The corresponding logic differs from the one used to update metrics
        // for individual components (they're different stored procs).
        //
        // To ensure consistency between the two paths, it's CRITICAL that both compute
        // the exact same data. This test is meant to assert this to detect unintended
        // drift later down the road.

        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        createTestConfigProperties();

        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln);

        final var componentClean = new Component();
        componentClean.setProject(project);
        componentClean.setName("acme-lib-clean");
        qm.createComponent(componentClean, false);

        final var componentVulnUnaudited = new Component();
        componentVulnUnaudited.setProject(project);
        componentVulnUnaudited.setName("acme-lib-vuln-unaudited");
        qm.createComponent(componentVulnUnaudited, false);
        qm.addVulnerability(vuln, componentVulnUnaudited, "none");

        final var componentVulnAudited = new Component();
        componentVulnAudited.setProject(project);
        componentVulnAudited.setName("acme-lib-vuln-audited");
        qm.createComponent(componentVulnAudited, false);
        qm.addVulnerability(vuln, componentVulnAudited, "none");
        qm.makeAnalysis(
                new MakeAnalysisCommand(componentVulnAudited, vuln)
                        .withState(AnalysisState.NOT_AFFECTED));

        final var componentVulnSuppressed = new Component();
        componentVulnSuppressed.setProject(project);
        componentVulnSuppressed.setName("acme-lib-vuln-suppressed");
        qm.createComponent(componentVulnSuppressed, false);
        qm.addVulnerability(vuln, componentVulnSuppressed, "none");
        qm.makeAnalysis(
                new MakeAnalysisCommand(componentVulnSuppressed, vuln)
                        .withState(AnalysisState.FALSE_POSITIVE)
                        .withSuppress(true));

        final var componentViolationUnaudited = new Component();
        componentViolationUnaudited.setProject(project);
        componentViolationUnaudited.setName("acme-lib-violation-unaudited");
        qm.createComponent(componentViolationUnaudited, false);
        createPolicyViolation(
                componentViolationUnaudited,
                Policy.ViolationState.FAIL,
                PolicyViolation.Type.LICENSE);

        final var componentViolationAudited = new Component();
        componentViolationAudited.setProject(project);
        componentViolationAudited.setName("acme-lib-violation-audited");
        qm.createComponent(componentViolationAudited, false);
        final var violationAudited = createPolicyViolation(
                componentViolationAudited,
                Policy.ViolationState.WARN,
                PolicyViolation.Type.OPERATIONAL);
        qm.makeViolationAnalysis(
                new MakeViolationAnalysisCommand(componentViolationAudited, violationAudited)
                        .withState(ViolationAnalysisState.APPROVED));

        final var componentViolationSuppressed = new Component();
        componentViolationSuppressed.setProject(project);
        componentViolationSuppressed.setName("acme-lib-violation-suppressed");
        qm.createComponent(componentViolationSuppressed, false);
        final var violationSuppressed = createPolicyViolation(
                componentViolationSuppressed,
                Policy.ViolationState.INFO,
                PolicyViolation.Type.SECURITY);
        qm.makeViolationAnalysis(
                new MakeViolationAnalysisCommand(componentViolationSuppressed, violationSuppressed)
                        .withState(ViolationAnalysisState.REJECTED)
                        .withSuppress(true));

        final List<Component> components = List.of(
                componentClean,
                componentVulnUnaudited,
                componentVulnAudited,
                componentVulnSuppressed,
                componentViolationUnaudited,
                componentViolationAudited,
                componentViolationSuppressed);

        executeActivity(project);

        final List<DependencyMetrics> projectLevelMetrics = components.stream()
                .map(component -> withJdbiHandle(handle -> handle
                        .attach(MetricsDao.class)
                        .getMostRecentDependencyMetrics(component.getId())))
                .toList();

        // Wipe all component metrics so the single-component procedure's
        // change detection cannot skip any insert.
        useJdbiHandle(handle -> handle.execute("DELETE FROM \"DEPENDENCYMETRICS\""));

        useJdbiHandle(handle -> {
            final var dao = handle.attach(MetricsDao.class);
            components.forEach(component -> dao.updateComponentMetrics(component.getUuid()));
        });

        for (int i = 0; i < components.size(); i++) {
            final long componentId = components.get(i).getId();
            final DependencyMetrics componentMetrics = withJdbiHandle(
                    handle -> handle
                            .attach(MetricsDao.class)
                            .getMostRecentDependencyMetrics(componentId));
            assertThat(componentMetrics)
                    .usingRecursiveComparison()
                    .ignoringFields("firstOccurrence", "lastOccurrence")
                    .isEqualTo(projectLevelMetrics.get(i));
        }
    }

    @Test
    void shouldCreateNewRowsOnNewDay() throws Exception {
        // Daily datapoint queries (portfolio metrics, PORTFOLIOMETRICS_GLOBAL, collection metrics)
        // rely on at least one PROJECTMETRICS row existing per project per day.
        // Snapshots of a previous day must never suppress an insert, even when their values are identical.

        createTestConfigProperties();

        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib-a");
        qm.createComponent(component, false);

        // Seed yesterday's rows, with values identical to what the metrics update will compute.
        final Date yesterday = Date.from(Instant.now().minus(Duration.ofDays(1)));
        useJdbiHandle(handle -> {
            final var dao = handle.attach(MetricsTestDao.class);
            dao.createPartitionForDaysAgo("PROJECTMETRICS", 1);
            dao.createPartitionForDaysAgo("DEPENDENCYMETRICS", 1);

            final var projectMetrics = new ProjectMetrics();
            projectMetrics.setProjectId(project.getId());
            projectMetrics.setComponents(1);
            projectMetrics.setFirstOccurrence(yesterday);
            projectMetrics.setLastOccurrence(yesterday);
            dao.createProjectMetrics(projectMetrics);

            final var dependencyMetrics = new DependencyMetrics();
            dependencyMetrics.setProjectId(project.getId());
            dependencyMetrics.setComponentId(component.getId());
            dependencyMetrics.setFirstOccurrence(yesterday);
            dependencyMetrics.setLastOccurrence(yesterday);
            dao.createDependencyMetrics(dependencyMetrics);
        });

        executeActivity(project);

        final List<ProjectMetrics> projectMetrics = withJdbiHandle(
                handle -> handle
                        .attach(MetricsDao.class)
                        .getProjectMetricsSince(project.getId(), Instant.EPOCH));
        assertThat(projectMetrics).hasSize(2);
        assertThat(projectMetrics.getLast().getLastOccurrence()).isAfter(yesterday);

        final List<DependencyMetrics> componentMetrics = withJdbiHandle(
                handle -> handle
                        .attach(MetricsDao.class)
                        .getDependencyMetricsSince(component.getId(), Instant.EPOCH));
        assertThat(componentMetrics).hasSize(2);
        assertThat(componentMetrics.getLast().getLastOccurrence()).isAfter(yesterday);
    }

    @Test
    void shouldCreateNewRowsWhenLatestRowHasNullColumns() throws Exception {
        // Some metric columns are nullable and may be NULL in rows migrated
        // from v4. Change detection must treat NULL as changed and insert a fresh row,
        // rather than silently skipping.

        createTestConfigProperties();

        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib-a");
        qm.createComponent(component, false);

        // Seed a row for the current day whose values match what the
        // metrics update will compute, then NULL out its nullable columns.
        useJdbiHandle(handle -> {
            final var dependencyMetrics = new DependencyMetrics();
            dependencyMetrics.setProjectId(project.getId());
            dependencyMetrics.setComponentId(component.getId());
            dependencyMetrics.setFirstOccurrence(Date.from(Instant.now().minus(Duration.ofMinutes(1))));
            dependencyMetrics.setLastOccurrence(Date.from(Instant.now().minus(Duration.ofMinutes(1))));
            handle.attach(MetricsTestDao.class).createDependencyMetrics(dependencyMetrics);

            handle.createUpdate("""
                            UPDATE "DEPENDENCYMETRICS"
                               SET "FINDINGS_TOTAL" = NULL
                                 , "FINDINGS_AUDITED" = NULL
                                 , "FINDINGS_UNAUDITED" = NULL
                                 , "UNASSIGNED_SEVERITY" = NULL
                             WHERE "COMPONENT_ID" = :componentId
                            """)
                    .bind("componentId", component.getId())
                    .execute();
        });

        executeActivity(project);

        final List<DependencyMetrics> componentMetrics = withJdbiHandle(
                handle -> handle
                        .attach(MetricsDao.class)
                        .getDependencyMetricsSince(component.getId(), Instant.EPOCH));
        assertThat(componentMetrics).hasSize(2);
    }

    private void executeActivity(Project project) throws Exception {
        activity.execute(null, UpdateProjectMetricsArg.newBuilder()
                .setProjectUuid(project.getUuid().toString())
                .build());
    }

}
