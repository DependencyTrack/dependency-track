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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.metrics;

import alpine.event.framework.EventService;
import net.jcip.annotations.NotThreadSafe;
import org.dependencytrack.event.CallbackEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.CallbackTask;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@NotThreadSafe
public class PortfolioMetricsUpdateTaskTest extends AbstractMetricsUpdateTaskTest {

    @BeforeClass
    public static void setUpClass() {
        EventService.getInstance().subscribe(ProjectMetricsUpdateEvent.class, ProjectMetricsUpdateTask.class);
        EventService.getInstance().subscribe(CallbackEvent.class, CallbackTask.class);
    }

    @AfterClass
    public static void tearDownClass() {
        EventService.getInstance().unsubscribe(ProjectMetricsUpdateTask.class);
        EventService.getInstance().unsubscribe(CallbackTask.class);
    }

    @Test
    public void testUpdateMetricsEmpty() {
        new PortfolioMetricsUpdateTask().inform(new PortfolioMetricsUpdateEvent());

        final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
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
    public void testUpdateMetricsUnchanged() {
        // Record initial portfolio metrics
        new PortfolioMetricsUpdateTask().inform(new PortfolioMetricsUpdateEvent());
        final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
        assertThat(metrics.getLastOccurrence()).isEqualTo(metrics.getFirstOccurrence());

        // Run the task a second time, without any metric being changed
        final var beforeSecondRun = new Date();
        new PortfolioMetricsUpdateTask().inform(new PortfolioMetricsUpdateEvent());

        // Ensure that the lastOccurrence timestamp was correctly updated
        qm.getPersistenceManager().refresh(metrics);
        assertThat(metrics.getLastOccurrence()).isNotEqualTo(metrics.getFirstOccurrence());
        assertThat(metrics.getLastOccurrence()).isAfterOrEqualTo(beforeSecondRun);
    }

    @Test
    public void testUpdateMetricsVulnerabilities() {
        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln, false);

        // Create a project with an unaudited vulnerability.
        var projectUnaudited = new Project();
        projectUnaudited.setName("acme-app-a");
        projectUnaudited = qm.createProject(projectUnaudited, List.of(), false);
        var componentUnaudited = new Component();
        componentUnaudited.setProject(projectUnaudited);
        componentUnaudited.setName("acme-lib-a");
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        qm.addVulnerability(vuln, componentUnaudited, AnalyzerIdentity.NONE);

        // Create a project with an audited vulnerability.
        var projectAudited = new Project();
        projectAudited.setName("acme-app-b");
        projectAudited = qm.createProject(projectAudited, List.of(), false);
        var componentAudited = new Component();
        componentAudited.setProject(projectAudited);
        componentAudited.setName("acme-lib-b");
        componentAudited = qm.createComponent(componentAudited, false);
        qm.addVulnerability(vuln, componentAudited, AnalyzerIdentity.NONE);
        qm.makeAnalysis(componentAudited, vuln, AnalysisState.NOT_AFFECTED, null, null, null, false);

        // Create a project with a suppressed vulnerability.
        var projectSuppressed = new Project();
        projectSuppressed.setName("acme-app-c");
        projectSuppressed = qm.createProject(projectSuppressed, List.of(), false);
        var componentSuppressed = new Component();
        componentSuppressed.setProject(projectSuppressed);
        componentSuppressed.setName("acme-lib-c");
        componentSuppressed = qm.createComponent(componentSuppressed, false);
        qm.addVulnerability(vuln, componentSuppressed, AnalyzerIdentity.NONE);
        qm.makeAnalysis(componentSuppressed, vuln, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        new PortfolioMetricsUpdateTask().inform(new PortfolioMetricsUpdateEvent());

        final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
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
    public void testUpdateMetricsPolicyViolations() {
        // Create a project with an unaudited violation.
        var projectUnaudited = new Project();
        projectUnaudited.setName("acme-app-a");
        projectUnaudited = qm.createProject(projectUnaudited, List.of(), false);
        var componentUnaudited = new Component();
        componentUnaudited.setProject(projectUnaudited);
        componentUnaudited.setName("acme-lib-a");
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        createPolicyViolation(componentUnaudited, Policy.ViolationState.FAIL, PolicyViolation.Type.LICENSE);

        // Create a project with an audited violation.
        var projectAudited = new Project();
        projectAudited.setName("acme-app-b");
        projectAudited = qm.createProject(projectAudited, List.of(), false);
        var componentAudited = new Component();
        componentAudited.setProject(projectAudited);
        componentAudited.setName("acme-lib-b");
        componentAudited = qm.createComponent(componentAudited, false);
        final var violationAudited = createPolicyViolation(componentAudited, Policy.ViolationState.WARN, PolicyViolation.Type.OPERATIONAL);
        qm.makeViolationAnalysis(componentAudited, violationAudited, ViolationAnalysisState.APPROVED, false);

        // Create a project with a suppressed violation.
        var projectSuppressed = new Project();
        projectSuppressed.setName("acme-app-c");
        projectSuppressed = qm.createProject(projectSuppressed, List.of(), false);
        var componentSuppressed = new Component();
        componentSuppressed.setProject(projectSuppressed);
        componentSuppressed.setName("acme-lib-c");
        componentSuppressed = qm.createComponent(componentSuppressed, false);
        final var violationSuppressed = createPolicyViolation(componentSuppressed, Policy.ViolationState.INFO, PolicyViolation.Type.SECURITY);
        qm.makeViolationAnalysis(componentSuppressed, violationSuppressed, ViolationAnalysisState.REJECTED, true);

        new PortfolioMetricsUpdateTask().inform(new PortfolioMetricsUpdateEvent());

        final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
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

}