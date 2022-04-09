package org.dependencytrack.tasks;

import org.dependencytrack.TaskTest;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Policy.ViolationState;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.MetricsUpdateTask.MetricCounters;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Test;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class MetricsUpdateTaskTest extends TaskTest {

    @Test
    public void testUpdatePortfolioMetricsEmpty() {
        final MetricCounters counters = new MetricsUpdateTask().updatePortfolioMetrics(qm);
        assertThat(counters.critical).isZero();
        assertThat(counters.high).isZero();
        assertThat(counters.medium).isZero();
        assertThat(counters.low).isZero();
        assertThat(counters.unassigned).isZero();
        assertThat(counters.projects).isZero();
        assertThat(counters.vulnerableProjects).isZero();
        assertThat(counters.components).isZero();
        assertThat(counters.vulnerableComponents).isZero();
        assertThat(counters.vulnerabilities).isZero();
        assertThat(counters.suppressions).isZero();
        assertThat(counters.findingsTotal).isZero();
        assertThat(counters.findingsAudited).isZero();
        assertThat(counters.findingsUnaudited).isZero();
        assertThat(counters.policyViolationsFail).isZero();
        assertThat(counters.policyViolationsWarn).isZero();
        assertThat(counters.policyViolationsInfo).isZero();
        assertThat(counters.policyViolationsTotal).isZero();
        assertThat(counters.policyViolationsAudited).isZero();
        assertThat(counters.policyViolationsUnaudited).isZero();
        assertThat(counters.policyViolationsSecurityTotal).isZero();
        assertThat(counters.policyViolationsSecurityAudited).isZero();
        assertThat(counters.policyViolationsSecurityUnaudited).isZero();
        assertThat(counters.policyViolationsLicenseTotal).isZero();
        assertThat(counters.policyViolationsLicenseAudited).isZero();
        assertThat(counters.policyViolationsLicenseUnaudited).isZero();
        assertThat(counters.policyViolationsOperationalTotal).isZero();
        assertThat(counters.policyViolationsOperationalAudited).isZero();
        assertThat(counters.policyViolationsOperationalUnaudited).isZero();
    }

    @Test
    public void testUpdatePortfolioMetricsVulnerabilities() {
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

        final MetricCounters counters = new MetricsUpdateTask().updatePortfolioMetrics(qm);
        assertThat(counters.critical).isZero();
        assertThat(counters.high).isEqualTo(2); // One is suppressed
        assertThat(counters.medium).isZero();
        assertThat(counters.low).isZero();
        assertThat(counters.unassigned).isZero();
        assertThat(counters.projects).isEqualTo(3);
        assertThat(counters.vulnerableProjects).isEqualTo(2); // Finding for one project is suppressed
        assertThat(counters.components).isEqualTo(3);
        assertThat(counters.vulnerableComponents).isEqualTo(2); // Finding for one component is suppressed
        assertThat(counters.vulnerabilities).isEqualTo(2); // One is suppressed
        assertThat(counters.suppressions).isEqualTo(1);
        assertThat(counters.findingsTotal).isEqualTo(2); // One is suppressed
        assertThat(counters.findingsAudited).isEqualTo(1);
        assertThat(counters.findingsUnaudited).isEqualTo(1);
        assertThat(counters.policyViolationsFail).isZero();
        assertThat(counters.policyViolationsWarn).isZero();
        assertThat(counters.policyViolationsInfo).isZero();
        assertThat(counters.policyViolationsTotal).isZero();
        assertThat(counters.policyViolationsAudited).isZero();
        assertThat(counters.policyViolationsUnaudited).isZero();
        assertThat(counters.policyViolationsSecurityTotal).isZero();
        assertThat(counters.policyViolationsSecurityAudited).isZero();
        assertThat(counters.policyViolationsSecurityUnaudited).isZero();
        assertThat(counters.policyViolationsLicenseTotal).isZero();
        assertThat(counters.policyViolationsLicenseAudited).isZero();
        assertThat(counters.policyViolationsLicenseUnaudited).isZero();
        assertThat(counters.policyViolationsOperationalTotal).isZero();
        assertThat(counters.policyViolationsOperationalAudited).isZero();
        assertThat(counters.policyViolationsOperationalUnaudited).isZero();
    }

    @Test
    public void testUpdatePortfolioMetricsPolicyViolations() {
        // Create a project with an unaudited violation.
        var projectUnaudited = new Project();
        projectUnaudited.setName("acme-app-a");
        projectUnaudited = qm.createProject(projectUnaudited, List.of(), false);
        var componentUnaudited = new Component();
        componentUnaudited.setProject(projectUnaudited);
        componentUnaudited.setName("acme-lib-a");
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        createPolicyViolation(componentUnaudited, ViolationState.FAIL, PolicyViolation.Type.LICENSE);

        // Create a project with an audited violation.
        var projectAudited = new Project();
        projectAudited.setName("acme-app-b");
        projectAudited = qm.createProject(projectAudited, List.of(), false);
        var componentAudited = new Component();
        componentAudited.setProject(projectAudited);
        componentAudited.setName("acme-lib-b");
        componentAudited = qm.createComponent(componentAudited, false);
        final var violationAudited = createPolicyViolation(componentAudited, ViolationState.WARN, PolicyViolation.Type.OPERATIONAL);
        qm.makeViolationAnalysis(componentAudited, violationAudited, ViolationAnalysisState.APPROVED, false);

        // Create a project with a suppressed violation.
        var projectSuppressed = new Project();
        projectSuppressed.setName("acme-app-c");
        projectSuppressed = qm.createProject(projectSuppressed, List.of(), false);
        var componentSuppressed = new Component();
        componentSuppressed.setProject(projectSuppressed);
        componentSuppressed.setName("acme-lib-c");
        componentSuppressed = qm.createComponent(componentSuppressed, false);
        final var violationSuppressed = createPolicyViolation(componentSuppressed, ViolationState.INFO, PolicyViolation.Type.SECURITY);
        qm.makeViolationAnalysis(componentSuppressed, violationSuppressed, ViolationAnalysisState.REJECTED, true);

        final MetricCounters counters = new MetricsUpdateTask().updatePortfolioMetrics(qm);
        assertThat(counters.critical).isZero();
        assertThat(counters.high).isZero();
        assertThat(counters.medium).isZero();
        assertThat(counters.low).isZero();
        assertThat(counters.unassigned).isZero();
        assertThat(counters.projects).isEqualTo(3);
        assertThat(counters.vulnerableProjects).isZero();
        assertThat(counters.components).isEqualTo(3);
        assertThat(counters.vulnerableComponents).isZero();
        assertThat(counters.vulnerabilities).isZero();
        assertThat(counters.suppressions).isZero();
        assertThat(counters.findingsTotal).isZero();
        assertThat(counters.findingsAudited).isZero();
        assertThat(counters.findingsUnaudited).isZero();
        assertThat(counters.policyViolationsFail).isEqualTo(1);
        assertThat(counters.policyViolationsWarn).isEqualTo(1);
        assertThat(counters.policyViolationsInfo).isZero(); // Suppressed
        assertThat(counters.policyViolationsTotal).isEqualTo(2);
        assertThat(counters.policyViolationsAudited).isEqualTo(1);
        assertThat(counters.policyViolationsUnaudited).isEqualTo(1);
        assertThat(counters.policyViolationsSecurityTotal).isZero(); // Suppressed
        assertThat(counters.policyViolationsSecurityAudited).isZero();
        assertThat(counters.policyViolationsSecurityUnaudited).isZero();
        assertThat(counters.policyViolationsLicenseTotal).isEqualTo(1);
        assertThat(counters.policyViolationsLicenseAudited).isZero();
        assertThat(counters.policyViolationsLicenseUnaudited).isEqualTo(1);
        assertThat(counters.policyViolationsOperationalTotal).isEqualTo(1);
        assertThat(counters.policyViolationsOperationalAudited).isEqualTo(1);
        assertThat(counters.policyViolationsOperationalUnaudited).isEqualTo(0);
    }

    @Test
    public void testUpdateProjectMetricsEmpty() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        final MetricCounters counters = new MetricsUpdateTask().updateProjectMetrics(qm, project.getId());
        assertThat(counters.critical).isZero();
        assertThat(counters.high).isZero();
        assertThat(counters.medium).isZero();
        assertThat(counters.low).isZero();
        assertThat(counters.unassigned).isZero();
        assertThat(counters.projects).isZero();
        assertThat(counters.vulnerableProjects).isZero();
        assertThat(counters.components).isZero();
        assertThat(counters.vulnerableComponents).isZero();
        assertThat(counters.vulnerabilities).isZero();
        assertThat(counters.suppressions).isZero();
        assertThat(counters.findingsTotal).isZero();
        assertThat(counters.findingsAudited).isZero();
        assertThat(counters.findingsUnaudited).isZero();
        assertThat(counters.policyViolationsFail).isZero();
        assertThat(counters.policyViolationsWarn).isZero();
        assertThat(counters.policyViolationsInfo).isZero();
        assertThat(counters.policyViolationsTotal).isZero();
        assertThat(counters.policyViolationsAudited).isZero();
        assertThat(counters.policyViolationsUnaudited).isZero();
        assertThat(counters.policyViolationsSecurityTotal).isZero();
        assertThat(counters.policyViolationsSecurityAudited).isZero();
        assertThat(counters.policyViolationsSecurityUnaudited).isZero();
        assertThat(counters.policyViolationsLicenseTotal).isZero();
        assertThat(counters.policyViolationsLicenseAudited).isZero();
        assertThat(counters.policyViolationsLicenseUnaudited).isZero();
        assertThat(counters.policyViolationsOperationalTotal).isZero();
        assertThat(counters.policyViolationsOperationalAudited).isZero();
        assertThat(counters.policyViolationsOperationalUnaudited).isZero();
    }

    @Test
    public void testUpdateProjectMetricsVulnerabilities() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var vuln = new Vulnerability();
        vuln.setVulnId("INTERNAL-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        vuln = qm.createVulnerability(vuln, false);

        // Create a component with an unaudited vulnerability.
        var componentUnaudited = new Component();
        componentUnaudited.setProject(project);
        componentUnaudited.setName("acme-lib-a");
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        qm.addVulnerability(vuln, componentUnaudited, AnalyzerIdentity.NONE);

        // Create a project with an audited vulnerability.
        var componentAudited = new Component();
        componentAudited.setProject(project);
        componentAudited.setName("acme-lib-b");
        componentAudited = qm.createComponent(componentAudited, false);
        qm.addVulnerability(vuln, componentAudited, AnalyzerIdentity.NONE);
        qm.makeAnalysis(componentAudited, vuln, AnalysisState.NOT_AFFECTED, null, null, null, false);

        // Create a project with a suppressed vulnerability.
        var componentSuppressed = new Component();
        componentSuppressed.setProject(project);
        componentSuppressed.setName("acme-lib-c");
        componentSuppressed = qm.createComponent(componentSuppressed, false);
        qm.addVulnerability(vuln, componentSuppressed, AnalyzerIdentity.NONE);
        qm.makeAnalysis(componentSuppressed, vuln, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        final MetricCounters counters = new MetricsUpdateTask().updateProjectMetrics(qm, project.getId());
        assertThat(counters.critical).isZero();
        assertThat(counters.high).isEqualTo(2); // One is suppressed
        assertThat(counters.medium).isZero();
        assertThat(counters.low).isZero();
        assertThat(counters.unassigned).isZero();
        assertThat(counters.projects).isZero();
        assertThat(counters.vulnerableProjects).isZero();
        assertThat(counters.components).isEqualTo(3);
        assertThat(counters.vulnerableComponents).isEqualTo(2); // Finding for one component is suppressed
        assertThat(counters.vulnerabilities).isEqualTo(2); // One is suppressed
        assertThat(counters.suppressions).isEqualTo(1);
        assertThat(counters.findingsTotal).isEqualTo(2); // One is suppressed
        assertThat(counters.findingsAudited).isEqualTo(1);
        assertThat(counters.findingsUnaudited).isEqualTo(1);
        assertThat(counters.policyViolationsFail).isZero();
        assertThat(counters.policyViolationsWarn).isZero();
        assertThat(counters.policyViolationsInfo).isZero();
        assertThat(counters.policyViolationsTotal).isZero();
        assertThat(counters.policyViolationsAudited).isZero();
        assertThat(counters.policyViolationsUnaudited).isZero();
        assertThat(counters.policyViolationsSecurityTotal).isZero();
        assertThat(counters.policyViolationsSecurityAudited).isZero();
        assertThat(counters.policyViolationsSecurityUnaudited).isZero();
        assertThat(counters.policyViolationsLicenseTotal).isZero();
        assertThat(counters.policyViolationsLicenseAudited).isZero();
        assertThat(counters.policyViolationsLicenseUnaudited).isZero();
        assertThat(counters.policyViolationsOperationalTotal).isZero();
        assertThat(counters.policyViolationsOperationalAudited).isZero();
        assertThat(counters.policyViolationsOperationalUnaudited).isZero();
    }

    @Test
    public void testUpdateProjectMetricsPolicyViolations() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        // Create a component with an unaudited violation.
        var componentUnaudited = new Component();
        componentUnaudited.setProject(project);
        componentUnaudited.setName("acme-lib-a");
        componentUnaudited = qm.createComponent(componentUnaudited, false);
        createPolicyViolation(componentUnaudited, ViolationState.FAIL, PolicyViolation.Type.LICENSE);

        // Create a component with an audited violation.
        var componentAudited = new Component();
        componentAudited.setProject(project);
        componentAudited.setName("acme-lib-b");
        componentAudited = qm.createComponent(componentAudited, false);
        final var violationAudited = createPolicyViolation(componentAudited, ViolationState.WARN, PolicyViolation.Type.OPERATIONAL);
        qm.makeViolationAnalysis(componentAudited, violationAudited, ViolationAnalysisState.APPROVED, false);

        // Create a component with a suppressed violation.
        var componentSuppressed = new Component();
        componentSuppressed.setProject(project);
        componentSuppressed.setName("acme-lib-c");
        componentSuppressed = qm.createComponent(componentSuppressed, false);
        final var violationSuppressed = createPolicyViolation(componentSuppressed, ViolationState.INFO, PolicyViolation.Type.SECURITY);
        qm.makeViolationAnalysis(componentSuppressed, violationSuppressed, ViolationAnalysisState.REJECTED, true);

        final MetricCounters counters = new MetricsUpdateTask().updateProjectMetrics(qm, project.getId());
        assertThat(counters.critical).isZero();
        assertThat(counters.high).isZero();
        assertThat(counters.medium).isZero();
        assertThat(counters.low).isZero();
        assertThat(counters.unassigned).isZero();
        assertThat(counters.projects).isZero();
        assertThat(counters.vulnerableProjects).isZero();
        assertThat(counters.components).isEqualTo(3);
        assertThat(counters.vulnerableComponents).isZero();
        assertThat(counters.vulnerabilities).isZero();
        assertThat(counters.suppressions).isZero();
        assertThat(counters.findingsTotal).isZero();
        assertThat(counters.findingsAudited).isZero();
        assertThat(counters.findingsUnaudited).isZero();
        assertThat(counters.policyViolationsFail).isEqualTo(1);
        assertThat(counters.policyViolationsWarn).isEqualTo(1);
        assertThat(counters.policyViolationsInfo).isZero(); // Suppressed
        assertThat(counters.policyViolationsTotal).isEqualTo(2);
        assertThat(counters.policyViolationsAudited).isEqualTo(1);
        assertThat(counters.policyViolationsUnaudited).isEqualTo(1);
        assertThat(counters.policyViolationsSecurityTotal).isZero(); // Suppressed
        assertThat(counters.policyViolationsSecurityAudited).isZero();
        assertThat(counters.policyViolationsSecurityUnaudited).isZero();
        assertThat(counters.policyViolationsLicenseTotal).isEqualTo(1);
        assertThat(counters.policyViolationsLicenseAudited).isZero();
        assertThat(counters.policyViolationsLicenseUnaudited).isEqualTo(1);
        assertThat(counters.policyViolationsOperationalTotal).isEqualTo(1);
        assertThat(counters.policyViolationsOperationalAudited).isEqualTo(1);
        assertThat(counters.policyViolationsOperationalUnaudited).isZero();
    }

    @Test
    public void testUpdateComponentMetricsEmpty() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.createComponent(component, false);

        final MetricCounters counters = new MetricsUpdateTask().updateComponentMetrics(qm, component.getId());
        assertThat(counters.critical).isZero();
        assertThat(counters.high).isZero();
        assertThat(counters.medium).isZero();
        assertThat(counters.low).isZero();
        assertThat(counters.unassigned).isZero();
        assertThat(counters.projects).isZero();
        assertThat(counters.vulnerableProjects).isZero();
        assertThat(counters.components).isZero();
        assertThat(counters.vulnerableComponents).isZero();
        assertThat(counters.vulnerabilities).isZero();
        assertThat(counters.suppressions).isZero();
        assertThat(counters.findingsTotal).isZero();
        assertThat(counters.findingsAudited).isZero();
        assertThat(counters.findingsUnaudited).isZero();
        assertThat(counters.policyViolationsFail).isZero();
        assertThat(counters.policyViolationsWarn).isZero();
        assertThat(counters.policyViolationsInfo).isZero();
        assertThat(counters.policyViolationsTotal).isZero();
        assertThat(counters.policyViolationsAudited).isZero();
        assertThat(counters.policyViolationsUnaudited).isZero();
        assertThat(counters.policyViolationsSecurityTotal).isZero();
        assertThat(counters.policyViolationsSecurityAudited).isZero();
        assertThat(counters.policyViolationsSecurityUnaudited).isZero();
        assertThat(counters.policyViolationsLicenseTotal).isZero();
        assertThat(counters.policyViolationsLicenseAudited).isZero();
        assertThat(counters.policyViolationsLicenseUnaudited).isZero();
        assertThat(counters.policyViolationsOperationalTotal).isZero();
        assertThat(counters.policyViolationsOperationalAudited).isZero();
        assertThat(counters.policyViolationsOperationalUnaudited).isZero();
    }

    @Test
    public void testUpdateComponentMetricsVulnerabilities() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.createComponent(component, false);

        // Create an unaudited vulnerability.
        var vulnUnaudited = new Vulnerability();
        vulnUnaudited.setVulnId("INTERNAL-001");
        vulnUnaudited.setSource(Vulnerability.Source.INTERNAL);
        vulnUnaudited.setSeverity(Severity.HIGH);
        vulnUnaudited = qm.createVulnerability(vulnUnaudited, false);
        qm.addVulnerability(vulnUnaudited, component, AnalyzerIdentity.NONE);

        // Create an audited vulnerability.
        var vulnAudited = new Vulnerability();
        vulnAudited.setVulnId("INTERNAL-002");
        vulnAudited.setSource(Vulnerability.Source.INTERNAL);
        vulnAudited.setSeverity(Severity.MEDIUM);
        vulnAudited = qm.createVulnerability(vulnAudited, false);
        qm.addVulnerability(vulnAudited, component, AnalyzerIdentity.NONE);
        qm.makeAnalysis(component, vulnAudited, AnalysisState.NOT_AFFECTED, null, null, null, false);

        // Create a suppressed vulnerability.
        var vulnSuppressed = new Vulnerability();
        vulnSuppressed.setVulnId("INTERNAL-003");
        vulnSuppressed.setSource(Vulnerability.Source.INTERNAL);
        vulnSuppressed.setSeverity(Severity.MEDIUM);
        vulnSuppressed = qm.createVulnerability(vulnSuppressed, false);
        qm.addVulnerability(vulnSuppressed, component, AnalyzerIdentity.NONE);
        qm.makeAnalysis(component, vulnSuppressed, AnalysisState.FALSE_POSITIVE, null, null, null, true);

        final MetricCounters counters = new MetricsUpdateTask().updateComponentMetrics(qm, component.getId());
        assertThat(counters.critical).isZero();
        assertThat(counters.high).isEqualTo(1);
        assertThat(counters.medium).isEqualTo(1); // One is suppressed
        assertThat(counters.low).isZero();
        assertThat(counters.unassigned).isZero();
        assertThat(counters.projects).isZero();
        assertThat(counters.vulnerableProjects).isZero();
        assertThat(counters.components).isZero();
        assertThat(counters.vulnerableComponents).isZero();
        assertThat(counters.vulnerabilities).isEqualTo(2); // One is suppressed
        assertThat(counters.suppressions).isEqualTo(1);
        assertThat(counters.findingsTotal).isEqualTo(2); // One is suppressed
        assertThat(counters.findingsAudited).isEqualTo(1);
        assertThat(counters.findingsUnaudited).isEqualTo(1);
        assertThat(counters.policyViolationsFail).isZero();
        assertThat(counters.policyViolationsWarn).isZero();
        assertThat(counters.policyViolationsInfo).isZero();
        assertThat(counters.policyViolationsTotal).isZero();
        assertThat(counters.policyViolationsAudited).isZero();
        assertThat(counters.policyViolationsUnaudited).isZero();
        assertThat(counters.policyViolationsSecurityTotal).isZero();
        assertThat(counters.policyViolationsSecurityAudited).isZero();
        assertThat(counters.policyViolationsSecurityUnaudited).isZero();
        assertThat(counters.policyViolationsLicenseTotal).isZero();
        assertThat(counters.policyViolationsLicenseAudited).isZero();
        assertThat(counters.policyViolationsLicenseUnaudited).isZero();
        assertThat(counters.policyViolationsOperationalTotal).isZero();
        assertThat(counters.policyViolationsOperationalAudited).isZero();
        assertThat(counters.policyViolationsOperationalUnaudited).isZero();
    }

    @Test
    public void testUpdateComponentMetricsPolicyViolations() {
        var project = new Project();
        project.setName("acme-app");
        project = qm.createProject(project, List.of(), false);

        var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component = qm.createComponent(component, false);

        // Create an unaudited violation.
        createPolicyViolation(component, ViolationState.FAIL, PolicyViolation.Type.LICENSE);

        // Create an audited violation.
        final PolicyViolation auditedViolation = createPolicyViolation(component, ViolationState.WARN, PolicyViolation.Type.OPERATIONAL);
        qm.makeViolationAnalysis(component, auditedViolation, ViolationAnalysisState.APPROVED, false);

        // Create a suppressed violation.
        final PolicyViolation suppressedViolation = createPolicyViolation(component, ViolationState.INFO, PolicyViolation.Type.SECURITY);
        qm.makeViolationAnalysis(component, suppressedViolation, ViolationAnalysisState.REJECTED, true);

        final MetricCounters counters = new MetricsUpdateTask().updateComponentMetrics(qm, component.getId());
        assertThat(counters.critical).isZero();
        assertThat(counters.high).isZero();
        assertThat(counters.medium).isZero();
        assertThat(counters.low).isZero();
        assertThat(counters.unassigned).isZero();
        assertThat(counters.projects).isZero();
        assertThat(counters.vulnerableProjects).isZero();
        assertThat(counters.components).isZero();
        assertThat(counters.vulnerableComponents).isZero();
        assertThat(counters.vulnerabilities).isZero();
        assertThat(counters.suppressions).isZero();
        assertThat(counters.findingsTotal).isZero();
        assertThat(counters.findingsAudited).isZero();
        assertThat(counters.findingsUnaudited).isZero();
        assertThat(counters.policyViolationsFail).isEqualTo(1);
        assertThat(counters.policyViolationsWarn).isEqualTo(1);
        assertThat(counters.policyViolationsInfo).isZero(); // Suppressed
        assertThat(counters.policyViolationsTotal).isEqualTo(2);
        assertThat(counters.policyViolationsAudited).isEqualTo(1);
        assertThat(counters.policyViolationsUnaudited).isEqualTo(1);
        assertThat(counters.policyViolationsSecurityTotal).isZero(); // Suppressed
        assertThat(counters.policyViolationsSecurityAudited).isZero();
        assertThat(counters.policyViolationsSecurityUnaudited).isZero();
        assertThat(counters.policyViolationsLicenseTotal).isEqualTo(1);
        assertThat(counters.policyViolationsLicenseAudited).isZero();
        assertThat(counters.policyViolationsLicenseUnaudited).isEqualTo(1);
        assertThat(counters.policyViolationsOperationalTotal).isEqualTo(1);
        assertThat(counters.policyViolationsOperationalAudited).isEqualTo(1);
        assertThat(counters.policyViolationsOperationalUnaudited).isZero();
    }

    private PolicyViolation createPolicyViolation(final Component component, final Policy.ViolationState violationState, final PolicyViolation.Type type) {
        final var policy = qm.createPolicy(UUID.randomUUID().toString(), Policy.Operator.ALL, violationState);
        final var policyCondition = qm.createPolicyCondition(policy, Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "");
        final var policyViolation = new PolicyViolation();

        policyViolation.setComponent(component);
        policyViolation.setPolicyCondition(policyCondition);
        policyViolation.setTimestamp(new Date());
        policyViolation.setType(type);
        return qm.addPolicyViolationIfNotExist(policyViolation);
    }

}