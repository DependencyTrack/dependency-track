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
package org.dependencytrack.policy;

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.License;
import org.dependencytrack.model.LicenseGroup;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Policy.Operator;
import org.dependencytrack.model.Policy.ViolationState;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.PolicyViolationIdentified;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

public class PolicyEngineTest extends PersistenceCapableTest {

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            NOTIFICATIONS.add(notification);
        }

    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    @BeforeClass
    public static void setUpClass() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));
    }

    @AfterClass
    public static void tearDownClass() {
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationSubscriber.class));
    }

    @Before
    public void setup() {
        NOTIFICATIONS.clear();
    }

    @After
    public void tearDown() {
        NOTIFICATIONS.clear();
    }

    @Test
    public void hasTagMatchPolicyLimitedToTag() {
        Policy policy = qm.createPolicy("Test Policy", Operator.ANY, ViolationState.INFO);
        qm.createPolicyCondition(policy, Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        Tag commonTag = qm.createTag("Tag 1");
        qm.bind(policy, List.of(commonTag));
        Project project = qm.createProject("My Project", null, "1", List.of(commonTag), null, null, true, false);
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0");
        component.setProject(project);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(project);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        PolicyEngine policyEngine = new PolicyEngine();
        List<PolicyViolation> violations = policyEngine.evaluate(List.of(component));
        Assert.assertEquals(1, violations.size());
    }

    @Test
    public void noTagMatchPolicyLimitedToTag() {
        Policy policy = qm.createPolicy("Test Policy", Operator.ANY, ViolationState.INFO);
        qm.createPolicyCondition(policy, Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        qm.bind(policy, List.of(qm.createTag("Tag 1")));
        Project project = qm.createProject("My Project", null, "1", List.of(qm.createTag("Tag 2")), null, null, true, false);
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0");
        component.setProject(project);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(project);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        PolicyEngine policyEngine = new PolicyEngine();
        List<PolicyViolation> violations = policyEngine.evaluate(List.of(component));
        Assert.assertEquals(0, violations.size());
    }

    @Test
    public void hasPolicyAssignedToParentProject() {
        Policy policy = qm.createPolicy("Test Policy", Operator.ANY, ViolationState.INFO);
        qm.createPolicyCondition(policy, Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        policy.setIncludeChildren(true);
        Project parent = qm.createProject("Parent", null, "1", null, null, null, true, false);
        Project child = qm.createProject("Child", null, "2", null, parent, null, true, false);
        Project grandchild = qm.createProject("Grandchild", null, "3", null, child, null, true, false);
        policy.setProjects(List.of(parent));
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0");
        component.setProject(grandchild);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(parent);
        qm.persist(child);
        qm.persist(grandchild);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        PolicyEngine policyEngine = new PolicyEngine();
        List<PolicyViolation> violations = policyEngine.evaluate(List.of(component));
        Assert.assertEquals(1, violations.size());
    }

    @Test
    public void noPolicyAssignedToParentProject() {
        Policy policy = qm.createPolicy("Test Policy", Operator.ANY, ViolationState.INFO);
        qm.createPolicyCondition(policy, Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        Project parent = qm.createProject("Parent", null, "1", null, null, null, true, false);
        Project child = qm.createProject("Child", null, "2", null, parent, null, true, false);
        Project grandchild = qm.createProject("Grandchild", null, "3", null, child, null, true, false);
        policy.setProjects(List.of(parent));
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0");
        component.setProject(grandchild);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(parent);
        qm.persist(child);
        qm.persist(grandchild);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        PolicyEngine policyEngine = new PolicyEngine();
        List<PolicyViolation> violations = policyEngine.evaluate(List.of(component));
        Assert.assertEquals(0, violations.size());
    }

    @Test
    public void policyForLatestTriggersOnLatestVersion() {
        Policy policy = qm.createPolicy("Test Policy", Operator.ANY, ViolationState.INFO, true);
        qm.createPolicyCondition(policy, Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        Project project = qm.createProject("My Project", null, "1", null, null,
                null, true, true, false);
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0");
        component.setProject(project);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(project);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        PolicyEngine policyEngine = new PolicyEngine();
        List<PolicyViolation> violations = policyEngine.evaluate(List.of(component));
        Assert.assertEquals(1, violations.size());
    }

    @Test
    public void policyForLatestTriggersNotOnNotLatestVersion() {
        Policy policy = qm.createPolicy("Test Policy", Operator.ANY, ViolationState.INFO, true);
        qm.createPolicyCondition(policy, Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        Project project = qm.createProject("My Project", null, "1", null, null,
                null, true, false, false);
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0");
        component.setProject(project);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(project);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        PolicyEngine policyEngine = new PolicyEngine();
        List<PolicyViolation> violations = policyEngine.evaluate(List.of(component));
        Assert.assertEquals(0, violations.size());
    }

    @Test
    public void determineViolationTypeTest() {
        PolicyCondition policyCondition = new PolicyCondition();
        policyCondition.setSubject(null);
        PolicyEngine policyEngine = new PolicyEngine();
        Assertions.assertNull(policyEngine.determineViolationType(policyCondition.getSubject()));
    }

    @Test
    public void issue1924() {
        Policy policy = qm.createPolicy("Policy 1924", Operator.ALL, ViolationState.INFO);
        qm.createPolicyCondition(policy, Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        qm.createPolicyCondition(policy, Subject.PACKAGE_URL, PolicyCondition.Operator.NO_MATCH, "pkg:deb");
        Project project = qm.createProject("My Project", null, "1", null, null, null, true, false);
        qm.persist(project);
        ArrayList<Component> components = new ArrayList<>();
        Component component = new Component();
        component.setName("OpenSSL");
        component.setVersion("3.0.2-0ubuntu1.6");
        component.setPurl("pkg:deb/openssl@3.0.2-0ubuntu1.6");
        component.setProject(project);
        components.add(component);
        qm.persist(component);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("1");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("2");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        component = new Component();
        component.setName("Log4J");
        component.setVersion("1.2.16");
        component.setPurl("pkg:mvn/log4j/log4j@1.2.16");
        component.setProject(project);
        components.add(component);
        qm.persist(component);
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("3");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        vulnerability = new Vulnerability();
        vulnerability.setVulnId("4");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.CRITICAL);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        PolicyEngine policyEngine = new PolicyEngine();
        List<PolicyViolation> violations = policyEngine.evaluate(components);
        Assert.assertEquals(3, violations.size());
        PolicyViolation policyViolation = violations.get(0);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(1);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(2);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(Subject.PACKAGE_URL, policyViolation.getPolicyCondition().getSubject());
    }

    @Test
    public void issue2455() {
        Policy policy = qm.createPolicy("Policy 1924", Operator.ALL, ViolationState.INFO);

        License license = new License();
        license.setName("Apache 2.0");
        license.setLicenseId("Apache-2.0");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        LicenseGroup lg = qm.createLicenseGroup("Test License Group 1");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        qm.createPolicyCondition(policy, Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());

        license = new License();
        license.setName("MIT");
        license.setLicenseId("MIT");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        lg = qm.createLicenseGroup("Test License Group 2");
        lg.setLicenses(Collections.singletonList(license));
        lg = qm.persist(lg);
        lg = qm.detach(LicenseGroup.class, lg.getId());
        license = qm.detach(License.class, license.getId());
        qm.createPolicyCondition(policy, Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());

        Project project = qm.createProject("My Project", null, "1", null, null, null, true, false);
        qm.persist(project);

        license = new License();
        license.setName("LGPL");
        license.setLicenseId("LGPL");
        license.setUuid(UUID.randomUUID());
        license = qm.persist(license);
        ArrayList<Component> components = new ArrayList<>();
        Component component = new Component();
        component.setName("Log4J");
        component.setVersion("2.0.0");
        component.setProject(project);
        component.setResolvedLicense(license);
        components.add(component);
        qm.persist(component);

        PolicyEngine policyEngine = new PolicyEngine();
        List<PolicyViolation> violations = policyEngine.evaluate(components);
        Assert.assertEquals(2, violations.size());
        PolicyViolation policyViolation = violations.get(0);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(Subject.LICENSE_GROUP, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(1);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(Subject.LICENSE_GROUP, policyViolation.getPolicyCondition().getSubject());
    }

    @Test
    public void notificationTest() {
        final var policy = qm.createPolicy("Test", Operator.ANY, ViolationState.FAIL);

        // Create a policy condition that matches on any coordinates.
        final var policyConditionA = qm.createPolicyCondition(policy, Subject.COORDINATES, PolicyCondition.Operator.MATCHES, """
                {"group": "*", name: "*", version: "*"}
                """);

        final var project = new Project();
        project.setName("Test Project");
        qm.createProject(project, Collections.emptyList(), false);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("foo");
        component.setName("bar");
        component.setVersion("1.2.3");
        qm.createComponent(component, false);

        // Evaluate policies and ensure that a notification has been sent.
        final var policyEngine = new PolicyEngine();
        assertThat(policyEngine.evaluate(List.of(component))).hasSize(1);
        assertThat(NOTIFICATIONS).hasSize(2);

        // Create an additional policy condition that matches on the exact version of the component,
        // and re-evaluate policies. Ensure that only one notification per newly violated condition was sent.
        final var policyConditionB = qm.createPolicyCondition(policy, Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.2.3");
        assertThat(policyEngine.evaluate(List.of(component))).hasSize(2);
        await("Notifications")
                .atMost(Duration.ofSeconds(3))
                .untilAsserted(() -> assertThat(NOTIFICATIONS).satisfiesExactly(
                        notification -> {
                            assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
                            assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_CREATED.name());
                        },
                        notification -> {
                            assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
                            assertThat(notification.getGroup()).isEqualTo(NotificationGroup.POLICY_VIOLATION.name());
                            assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
                            assertThat(notification.getSubject()).isInstanceOf(PolicyViolationIdentified.class);
                            final var subject = (PolicyViolationIdentified) notification.getSubject();
                            assertThat(subject.getComponent().getUuid()).isEqualTo(component.getUuid());
                            assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid());
                            assertThat(subject.getPolicyViolation().getPolicyCondition().getUuid()).isEqualTo(policyConditionA.getUuid());
                        },
                        notification -> {
                            assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
                            assertThat(notification.getGroup()).isEqualTo(NotificationGroup.POLICY_VIOLATION.name());
                            assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
                            assertThat(notification.getSubject()).isInstanceOf(PolicyViolationIdentified.class);
                            final var subject = (PolicyViolationIdentified) notification.getSubject();
                            assertThat(subject.getComponent().getUuid()).isEqualTo(component.getUuid());
                            assertThat(subject.getProject().getUuid()).isEqualTo(project.getUuid());
                            assertThat(subject.getPolicyViolation().getPolicyCondition().getUuid()).isEqualTo(policyConditionB.getUuid());
                        }));

        // Delete a policy condition and re-evaluate policies again. No new notifications should be sent.
        qm.deletePolicyCondition(policyConditionA);
        assertThat(policyEngine.evaluate(List.of(component))).hasSize(1);
        assertThat(NOTIFICATIONS).hasSize(3);
    }

    @Test
    public void violationReconciliationTest() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("org.acme");
        component.setName("acme-lib");
        component.setVersion("2.0.0");
        qm.persist(component);

        final Policy policyA = qm.createPolicy("Policy A", Operator.ANY, ViolationState.FAIL);
        qm.createPolicyCondition(policyA, Subject.COORDINATES, PolicyCondition.Operator.MATCHES, """
                {"group": "*", name: "*", version: "*"}
                """);

        // Create another policy which already has a violation files for the component.
        // The violation has both an analysis (REJECTED), and a comment added to it.
        // As it is checking for component version == 1.5.0, it should no longer violate and be cleaned up.
        final Policy policyB = qm.createPolicy("Policy B", Operator.ANY, ViolationState.FAIL);
        final PolicyCondition conditionB = qm.createPolicyCondition(policyB, Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.5.0");
        final var violationB = new PolicyViolation();
        violationB.setComponent(component);
        violationB.setPolicyCondition(conditionB);
        violationB.setTimestamp(Date.from(Instant.EPOCH));
        violationB.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(violationB);
        final var violationAnalysisB = qm.makeViolationAnalysis(component, violationB, ViolationAnalysisState.REJECTED, false);
        qm.makeViolationAnalysisComment(violationAnalysisB, "comment", "commenter");

        final var policyEngine = new PolicyEngine();
        assertThat(policyEngine.evaluate(List.of(component))).satisfiesExactly(violation ->
                assertThat(violation.getPolicyCondition().getPolicy().getName()).isEqualTo("Policy A"));
    }

    @Test
    public void violationReconciliationWithDuplicatesTest() {
        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("acme-lib-a");
        qm.persist(componentA);
        final var componentB = new Component();
        componentB.setProject(project);
        componentB.setName("acme-lib-b");
        qm.persist(componentB);
        final var componentC = new Component();
        componentC.setProject(project);
        componentC.setName("acme-lib-c");
        qm.persist(componentC);
        final var componentD = new Component();
        componentD.setProject(project);
        componentD.setName("acme-lib-d");
        qm.persist(componentD);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Operator.ALL);
        policy.setViolationState(ViolationState.INFO);
        qm.persist(policy);

        final var policyCondition = new PolicyCondition();
        policyCondition.setPolicy(policy);
        policyCondition.setSubject(Subject.COORDINATES);
        policyCondition.setOperator(PolicyCondition.Operator.MATCHES);
        policyCondition.setValue("""
                {name: "*"}
                """);
        qm.persist(policyCondition);

        final var violationTimestamp = new Date();

        // Create two identical violations for component A.
        final var policyViolationComponentA = new PolicyViolation();
        policyViolationComponentA.setPolicyCondition(policyCondition);
        policyViolationComponentA.setComponent(componentA);
        policyViolationComponentA.setTimestamp(violationTimestamp);
        policyViolationComponentA.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyViolationComponentA);
        final var policyViolationDuplicateComponentA = new PolicyViolation();
        policyViolationDuplicateComponentA.setPolicyCondition(policyCondition);
        policyViolationDuplicateComponentA.setComponent(componentA);
        policyViolationDuplicateComponentA.setTimestamp(violationTimestamp);
        policyViolationDuplicateComponentA.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyViolationDuplicateComponentA);

        // Create two almost identical violations for component B,
        // where one of them is older than the other.
        final var policyViolationComponentB = new PolicyViolation();
        policyViolationComponentB.setPolicyCondition(policyCondition);
        policyViolationComponentB.setComponent(componentB);
        policyViolationComponentB.setTimestamp(violationTimestamp);
        policyViolationComponentB.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyViolationComponentB);
        final var policyViolationDuplicateComponentB = new PolicyViolation();
        policyViolationDuplicateComponentB.setPolicyCondition(policyCondition);
        policyViolationDuplicateComponentB.setComponent(componentB);
        policyViolationDuplicateComponentB.setTimestamp(Date.from(Instant.now().minus(5, ChronoUnit.MINUTES)));
        policyViolationDuplicateComponentB.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyViolationDuplicateComponentB);

        // Create two identical violations for component C.
        // Only one of them has an analysis.
        final var policyViolationComponentC = new PolicyViolation();
        policyViolationComponentC.setPolicyCondition(policyCondition);
        policyViolationComponentC.setComponent(componentC);
        policyViolationComponentC.setTimestamp(violationTimestamp);
        policyViolationComponentC.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyViolationComponentC);
        final var policyViolationDuplicateComponentC = new PolicyViolation();
        policyViolationDuplicateComponentC.setPolicyCondition(policyCondition);
        policyViolationDuplicateComponentC.setComponent(componentC);
        policyViolationDuplicateComponentC.setTimestamp(violationTimestamp);
        policyViolationDuplicateComponentC.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyViolationDuplicateComponentC);
        final var violationAnalysisDuplicateComponentC = new ViolationAnalysis();
        violationAnalysisDuplicateComponentC.setPolicyViolation(policyViolationDuplicateComponentC);
        violationAnalysisDuplicateComponentC.setComponent(componentC);
        violationAnalysisDuplicateComponentC.setViolationAnalysisState(ViolationAnalysisState.APPROVED);
        qm.persist(violationAnalysisDuplicateComponentC);

        // Create two identical violations for component D.
        // Both have an analysis, but only one of them is suppressed.
        final var policyViolationComponentD = new PolicyViolation();
        policyViolationComponentD.setPolicyCondition(policyCondition);
        policyViolationComponentD.setComponent(componentD);
        policyViolationComponentD.setTimestamp(violationTimestamp);
        policyViolationComponentD.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyViolationComponentD);
        final var violationAnalysisComponentD = new ViolationAnalysis();
        violationAnalysisComponentD.setPolicyViolation(policyViolationComponentD);
        violationAnalysisComponentD.setComponent(componentD);
        violationAnalysisComponentD.setViolationAnalysisState(ViolationAnalysisState.REJECTED);
        qm.persist(violationAnalysisComponentD);
        final var policyViolationDuplicateComponentD = new PolicyViolation();
        policyViolationDuplicateComponentD.setPolicyCondition(policyCondition);
        policyViolationDuplicateComponentD.setComponent(componentD);
        policyViolationDuplicateComponentD.setTimestamp(violationTimestamp);
        policyViolationDuplicateComponentD.setType(PolicyViolation.Type.OPERATIONAL);
        qm.persist(policyViolationDuplicateComponentD);
        final var violationAnalysisDuplicateComponentD = new ViolationAnalysis();
        violationAnalysisDuplicateComponentD.setPolicyViolation(policyViolationDuplicateComponentD);
        violationAnalysisDuplicateComponentD.setComponent(componentD);
        violationAnalysisDuplicateComponentD.setViolationAnalysisState(ViolationAnalysisState.REJECTED);
        violationAnalysisDuplicateComponentD.setSuppressed(true);
        qm.persist(violationAnalysisDuplicateComponentD);

        final var policyEngine = new PolicyEngine();
        policyEngine.evaluate(List.of(componentA, componentB, componentC, componentD));

        // For component A, the first violation (i.e. lower ID) must be kept.
        assertThat(qm.getAllPolicyViolations(componentA, /* includeSuppressed */ true)).satisfiesExactlyInAnyOrder(
                violation -> assertThat(violation.getId()).isEqualTo(policyViolationComponentA.getId()));

        // For component B, the older violation must be kept.
        assertThat(qm.getAllPolicyViolations(componentB, /* includeSuppressed */ true)).satisfiesExactlyInAnyOrder(
                violation -> assertThat(violation.getId()).isEqualTo(policyViolationDuplicateComponentB.getId()));

        // For component C, the violation with analysis must be kept.
        assertThat(qm.getAllPolicyViolations(componentC, /* includeSuppressed */ true)).satisfiesExactlyInAnyOrder(
                violation -> assertThat(violation.getId()).isEqualTo(policyViolationDuplicateComponentC.getId()));

        // For component D, the suppressed violation must be kept.
        assertThat(qm.getAllPolicyViolations(componentD, /* includeSuppressed */ true)).satisfiesExactlyInAnyOrder(
                violation -> assertThat(violation.getId()).isEqualTo(policyViolationDuplicateComponentD.getId()));
    }

}