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
package org.dependencytrack.tasks.metrics;

import org.dependencytrack.event.ProjectMetricsUpdateEvent;
import org.dependencytrack.model.*;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Test;

import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class ProjectMetricsUpdateTaskTest extends AbstractMetricsUpdateTaskTest {

    @Test
    public void testUpdateMetricsEmpty() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
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

        qm.getPersistenceManager().refresh(project);
        assertThat(project.getLastInheritedRiskScore()).isZero();
    }

    @Test
    public void testUpdateMetricsUnchanged() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        // Record initial project metrics
        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));
        final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getLastOccurrence()).isEqualTo(metrics.getFirstOccurrence());

        // Run the task a second time, without any metric being changed
        final var beforeSecondRun = new Date();
        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        // Ensure that the lastOccurrence timestamp was correctly updated
        qm.getPersistenceManager().refresh(metrics);
        assertThat(metrics.getLastOccurrence()).isNotEqualTo(metrics.getFirstOccurrence());
        assertThat(metrics.getLastOccurrence()).isAfterOrEqualTo(beforeSecondRun);
    }

    @Test
    public void testUpdateMetricsVulnerabilities() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var vuln = this.prepareVulnerability("");

        // Create a component with an unaudited vulnerability.
        var componentUnaudited = this.prepareVulnerableComponent("acme-lib-a", vuln, project);

        // Create a project with an audited vulnerability.
        var componentAudited = this.prepareVulnerableComponent("acme-lib-b", vuln, project);
        qm.makeAnalysis(componentAudited, vuln, AnalysisState.NOT_AFFECTED, null, null, null, false);

        // Create a project with a suppressed vulnerability.
        var componentSuppressed = this.prepareVulnerableComponent("acme-lib-c", vuln, project);
        qm.makeAnalysis(componentSuppressed, vuln, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
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

        qm.getPersistenceManager().refreshAll(project, componentUnaudited, componentAudited, componentSuppressed);
        assertThat(project.getLastInheritedRiskScore()).isEqualTo(10.0);
        assertThat(componentUnaudited.getLastInheritedRiskScore()).isEqualTo(5.0);
        assertThat(componentAudited.getLastInheritedRiskScore()).isEqualTo(5.0);
        assertThat(componentSuppressed.getLastInheritedRiskScore()).isZero();
    }

    @Test
    public void testUpdateMetricsPolicyViolations() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        // Create a component with an unaudited violation.
        var componentUnaudited = new Component();
        componentUnaudited.setProject(project);
        componentUnaudited.setName("acme-lib-a");
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        createPolicyViolation(componentUnaudited, Policy.ViolationState.FAIL, PolicyViolation.Type.LICENSE);

        // Create a component with an audited violation.
        var componentAudited = new Component();
        componentAudited.setProject(project);
        componentAudited.setName("acme-lib-b");
        componentAudited = qm.createComponent(componentAudited, false);
        final var violationAudited = createPolicyViolation(componentAudited, Policy.ViolationState.WARN, PolicyViolation.Type.OPERATIONAL);
        qm.makeViolationAnalysis(componentAudited, violationAudited, ViolationAnalysisState.APPROVED, false);

        // Create a component with a suppressed violation.
        var componentSuppressed = new Component();
        componentSuppressed.setProject(project);
        componentSuppressed.setName("acme-lib-c");
        componentSuppressed = qm.createComponent(componentSuppressed, false);
        final var violationSuppressed = createPolicyViolation(componentSuppressed, Policy.ViolationState.INFO, PolicyViolation.Type.SECURITY);
        qm.makeViolationAnalysis(componentSuppressed, violationSuppressed, ViolationAnalysisState.REJECTED, true);

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
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

        qm.getPersistenceManager().refreshAll(project, componentUnaudited, componentAudited, componentSuppressed);
        assertThat(project.getLastInheritedRiskScore()).isZero();
        assertThat(componentUnaudited.getLastInheritedRiskScore()).isZero();
        assertThat(componentAudited.getLastInheritedRiskScore()).isZero();
        assertThat(componentSuppressed.getLastInheritedRiskScore()).isZero();
    }

    @Test
    public void testCollectionProjectMetricsAggregatingAllChildren() {
        var project = new Project();
        project.setActive(true);
        project.setName("testCollectionProjectMetricsAggregatingAllChildren");
        project.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        project = qm.createProject(project, List.of(), false);
        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        // add vulnerable projects as children
        this.prepareProjectWithVulns("test1_", project, null);
        Project child2 = this.prepareProjectWithVulns("test2_", project, null);

        // add another vulnerability to second child
        Vulnerability vuln2 = this.prepareVulnerability("test3_");
        this.prepareVulnerableComponent("test3_vulnComponent", vuln2, child2);
        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(child2.getUuid()));

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getComponents()).isEqualTo(7);
        assertThat(metrics.getVulnerableComponents()).isEqualTo(5); // Finding for 2 components is suppressed
        assertThat(metrics.getCritical()).isZero();
        assertThat(metrics.getHigh()).isEqualTo(5); // 2 are suppressed
        assertThat(metrics.getMedium()).isZero();
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isZero();
        assertThat(metrics.getVulnerabilities()).isEqualTo(5); // 2 are suppressed
        assertThat(metrics.getSuppressed()).isEqualTo(2);
        assertThat(metrics.getFindingsTotal()).isEqualTo(5); // 2 are suppressed
        assertThat(metrics.getFindingsAudited()).isEqualTo(2);
        assertThat(metrics.getFindingsUnaudited()).isEqualTo(3);
        assertThat(metrics.getInheritedRiskScore()).isEqualTo(25.0);
    }

    @Test
    public void testCollectionProjectMetricsAggregatingTaggedChildren() {
        Tag tag = qm.createTag("prod");
        var project = new Project();
        project.setActive(true);
        project.setName("testCollectionProjectMetricsAggregatingTaggedChildren");
        project.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG);
        project.setCollectionTag(tag);
        project = qm.createProject(project, List.of(), false);
        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        // add vulnerable projects as children
        this.prepareProjectWithVulns("test4_", project, null);
        Project child2 = this.prepareProjectWithVulns("test5_", project, null);
        Project child3 = this.prepareProjectWithVulns("test6_", project, null);

        // add another vulnerability to second child
        Vulnerability vuln2 = this.prepareVulnerability("test7_");
        this.prepareVulnerableComponent("test7_vulnComponent", vuln2, child2);
        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(child2.getUuid()));

        // add tags to child 2+3
        qm.bind(child2, List.of(tag));
        qm.bind(child3, List.of(tag));

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getComponents()).isEqualTo(7);
        assertThat(metrics.getVulnerableComponents()).isEqualTo(5); // Finding for 2 components is suppressed
        assertThat(metrics.getCritical()).isZero();
        assertThat(metrics.getHigh()).isEqualTo(5); // 2 are suppressed
        assertThat(metrics.getMedium()).isZero();
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isZero();
        assertThat(metrics.getVulnerabilities()).isEqualTo(5); // 2 are suppressed
        assertThat(metrics.getSuppressed()).isEqualTo(2);
        assertThat(metrics.getFindingsTotal()).isEqualTo(5); // 2 are suppressed
        assertThat(metrics.getFindingsAudited()).isEqualTo(2);
        assertThat(metrics.getFindingsUnaudited()).isEqualTo(3);
        assertThat(metrics.getInheritedRiskScore()).isEqualTo(25.0);
    }

    @Test
    public void testCollectionProjectMetricsSemVerChild() {
        Tag tag = qm.createTag("prod");
        var project = new Project();
        project.setActive(true);
        project.setName("testCollectionProjectMetricsSemVerChild");
        project.setCollectionLogic(ProjectCollectionLogic.HIGHEST_SEMVER_CHILD);
        project = qm.createProject(project, List.of(), false);
        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        // add vulnerable projects as children
        this.prepareProjectWithVulns("test8_", project, "1.2.3");
        Project child2 = this.prepareProjectWithVulns("test9_", project, "1.5.0");
        this.prepareProjectWithVulns("test10_", project, "1.2.4");

        // add another vulnerability to second child
        Vulnerability vuln2 = this.prepareVulnerability("test11_");
        this.prepareVulnerableComponent("test11_vulnComponent", vuln2, child2);
        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(child2.getUuid()));


        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));

        final ProjectMetrics metrics = qm.getMostRecentProjectMetrics(project);
        assertThat(metrics.getComponents()).isEqualTo(4);
        assertThat(metrics.getVulnerableComponents()).isEqualTo(3); // Finding for 1 components is suppressed
        assertThat(metrics.getCritical()).isZero();
        assertThat(metrics.getHigh()).isEqualTo(3); // 1 are suppressed
        assertThat(metrics.getMedium()).isZero();
        assertThat(metrics.getLow()).isZero();
        assertThat(metrics.getUnassigned()).isZero();
        assertThat(metrics.getVulnerabilities()).isEqualTo(3); // 1 are suppressed
        assertThat(metrics.getSuppressed()).isEqualTo(1);
        assertThat(metrics.getFindingsTotal()).isEqualTo(3); // 1 are suppressed
        assertThat(metrics.getFindingsAudited()).isEqualTo(1);
        assertThat(metrics.getFindingsUnaudited()).isEqualTo(2);
        assertThat(metrics.getInheritedRiskScore()).isEqualTo(15.0);
    }

    private Project prepareProjectWithVulns(String prefix, Project parent, String version) {
        var project = new Project();
        project.setActive(true);
        project.setParent(parent);
        project.setName(prefix + "acme-app");
        project.setVersion(version);
        project = qm.createProject(project, List.of(), false);

        var vuln = this.prepareVulnerability(prefix);
        // Create a component with an unaudited vulnerability.
        var componentUnaudited = this.prepareVulnerableComponent(prefix + "acme-lib-a", vuln, project);

        // Create a project with an audited vulnerability.
        var componentAudited = this.prepareVulnerableComponent(prefix + "acme-lib-b", vuln, project);
        qm.makeAnalysis(componentAudited, vuln, AnalysisState.NOT_AFFECTED, null, null, null, false);

        // Create a project with a suppressed vulnerability.
        var componentSuppressed = this.prepareVulnerableComponent(prefix + "acme-lib-c", vuln, project);
        qm.makeAnalysis(componentSuppressed, vuln, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        new ProjectMetricsUpdateTask().inform(new ProjectMetricsUpdateEvent(project.getUuid()));
        return project;
    }

    private Vulnerability prepareVulnerability(String prefix) {
        var vuln = new Vulnerability();
        vuln.setVulnId(prefix + "INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        return qm.createVulnerability(vuln, false);
    }

    private Component prepareVulnerableComponent(String name, Vulnerability vuln, Project project) {
        // Create a component with an unaudited vulnerability.
        var componentUnaudited = new Component();
        componentUnaudited.setProject(project);
        componentUnaudited.setName(name);
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        qm.addVulnerability(vuln, componentUnaudited, AnalyzerIdentity.NONE);
        return componentUnaudited;
    }

}