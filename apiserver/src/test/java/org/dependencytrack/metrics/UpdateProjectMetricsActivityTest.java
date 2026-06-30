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
    void shouldUpdateMetricsUnchanged() throws Exception {
        final var project = new Project();
        project.setName("acme-app");
        qm.createProject(project, List.of(), false);

        // Create risk score configproperties
        createTestConfigProperties();

        // Record initial project metrics
        executeActivity(project);
        final ProjectMetrics metrics = withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(metrics.getLastOccurrence()).isEqualTo(metrics.getFirstOccurrence());

        // Run the task a second time, without any metric being changed
        final var beforeSecondRun = new Date();
        executeActivity(project);

        // Two records should be created in today's partition since it's append-only
        final var recentMetrics = withJdbiHandle(handle -> handle.attach(MetricsDao.class).getMostRecentProjectMetrics(project.getId()));
        assertThat(recentMetrics.getLastOccurrence()).isNotEqualTo(metrics.getFirstOccurrence());
        assertThat(recentMetrics.getLastOccurrence()).isAfterOrEqualTo(beforeSecondRun);
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

    private void executeActivity(Project project) throws Exception {
        activity.execute(null, UpdateProjectMetricsArg.newBuilder()
                .setProjectUuid(project.getUuid().toString())
                .build());
    }

}
