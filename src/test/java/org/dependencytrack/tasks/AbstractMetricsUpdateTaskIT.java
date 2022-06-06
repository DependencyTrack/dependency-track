package org.dependencytrack.tasks;

import alpine.server.persistence.PersistenceManagerFactory;
import org.dependencytrack.event.MetricsUpdateEvent;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.PortfolioMetrics;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityMetrics;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

abstract class AbstractMetricsUpdateTaskIT {

    abstract void setUpDatabase() throws Exception;

    @Before
    public void setUp() throws Exception {
        setUpDatabase();
    }

    @After
    public void tearDown() {
        PersistenceManagerFactory.tearDown();
    }

    @Test
    public void testPortfolioMetricsUpdate() {
        try (final var qm = new QueryManager()) {
            var project = new Project();
            project.setName("acme-app");
            qm.createProject(project, List.of(), false);

            var component = new Component();
            component.setProject(project);
            component.setName("acme-lib");
            component = qm.createComponent(component, false);


            var vuln = new Vulnerability();
            vuln.setVulnId("INTERNAL-001");
            vuln.setSource(Vulnerability.Source.INTERNAL);
            vuln.setSeverity(Severity.HIGH);
            vuln = qm.createVulnerability(vuln, false);
            qm.addVulnerability(vuln, component, AnalyzerIdentity.NONE);
            qm.makeAnalysis(component, vuln, AnalysisState.NOT_AFFECTED, null, null, null, false);

            final var policy = qm.createPolicy(UUID.randomUUID().toString(), Policy.Operator.ALL, Policy.ViolationState.FAIL);
            final var policyCondition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "");
            var policyViolation = new PolicyViolation();
            policyViolation.setComponent(component);
            policyViolation.setPolicyCondition(policyCondition);
            policyViolation.setTimestamp(new Date());
            policyViolation.setType(PolicyViolation.Type.OPERATIONAL);
            policyViolation = qm.addPolicyViolationIfNotExist(policyViolation);
            qm.makeViolationAnalysis(component, policyViolation, ViolationAnalysisState.APPROVED, false);
        }

        new MetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.PORTFOLIO));

        try (final var qm = new QueryManager()) {
            final PortfolioMetrics metrics = qm.getMostRecentPortfolioMetrics();
            assertThat(metrics).isNotNull();
            assertThat(metrics.getProjects()).isEqualTo(1);
            assertThat(metrics.getVulnerableProjects()).isEqualTo(1);
            assertThat(metrics.getComponents()).isEqualTo(1);
            assertThat(metrics.getVulnerableComponents()).isEqualTo(1);
            assertThat(metrics.getCritical()).isZero();
            assertThat(metrics.getHigh()).isEqualTo(1);
            assertThat(metrics.getMedium()).isZero();
            assertThat(metrics.getLow()).isZero();
            assertThat(metrics.getUnassigned()).isZero();
            assertThat(metrics.getVulnerabilities()).isEqualTo(1);
            assertThat(metrics.getSuppressed()).isZero();
            assertThat(metrics.getFindingsTotal()).isEqualTo(1);
            assertThat(metrics.getFindingsAudited()).isEqualTo(1);
            assertThat(metrics.getFindingsUnaudited()).isZero();
            assertThat(metrics.getInheritedRiskScore()).isEqualTo(5.0);
            assertThat(metrics.getPolicyViolationsFail()).isEqualTo(1);
            assertThat(metrics.getPolicyViolationsWarn()).isZero();
            assertThat(metrics.getPolicyViolationsInfo()).isZero();
            assertThat(metrics.getPolicyViolationsTotal()).isEqualTo(1);
            assertThat(metrics.getPolicyViolationsAudited()).isEqualTo(1);
            assertThat(metrics.getPolicyViolationsUnaudited()).isEqualTo(0);
            assertThat(metrics.getPolicyViolationsSecurityTotal()).isZero();
            assertThat(metrics.getPolicyViolationsSecurityAudited()).isZero();
            assertThat(metrics.getPolicyViolationsSecurityUnaudited()).isZero();
            assertThat(metrics.getPolicyViolationsLicenseTotal()).isZero();
            assertThat(metrics.getPolicyViolationsLicenseAudited()).isZero();
            assertThat(metrics.getPolicyViolationsLicenseUnaudited()).isZero();
            assertThat(metrics.getPolicyViolationsOperationalTotal()).isEqualTo(1);
            assertThat(metrics.getPolicyViolationsOperationalAudited()).isEqualTo(1);
            assertThat(metrics.getPolicyViolationsOperationalUnaudited()).isZero();
        }
    }

    @Test
    public void testVulnerabilityMetricsUpdate() {
        try (final var qm = new QueryManager()) {
            // Test that paging works by creating more vulnerabilities
            // than fit on a single page (of size 500). Paging currently
            // the primary area where the supported databases behave differently.
            for (int i = 0; i < 750; i++) {
                var vuln = new Vulnerability();
                vuln.setVulnId("INTERNAL-" + i);
                vuln.setSource(Vulnerability.Source.INTERNAL);
                vuln.setSeverity(Severity.HIGH);
                vuln.setCreated(Date.from(LocalDateTime.of(2020, 10, 1, 6, 6, 6).toInstant(ZoneOffset.UTC)));
                qm.createVulnerability(vuln, false);
            }
        }

        new MetricsUpdateTask().inform(new MetricsUpdateEvent(MetricsUpdateEvent.Type.VULNERABILITY));

        try (final var qm = new QueryManager()) {
            final List<VulnerabilityMetrics> metrics = qm.getVulnerabilityMetrics();

            assertThat(metrics).hasSize(2);
            assertThat(metrics).satisfiesExactlyInAnyOrder(
                vm -> {
                    assertThat(vm.getYear()).isEqualTo(2020);
                    assertThat(vm.getMonth()).isNull();
                    assertThat(vm.getCount()).isEqualTo(750);
                },
                vm -> {
                    assertThat(vm.getYear()).isEqualTo(2020);
                    assertThat(vm.getMonth()).isEqualTo(10);
                    assertThat(vm.getCount()).isEqualTo(750);
                }
            );
        }
    }

}
