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
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import static org.assertj.core.api.Assertions.assertThat;

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
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        Tag commonTag = qm.createTag("Tag 1");
        policy.setTags(List.of(commonTag));
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
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        policy.setTags(List.of(qm.createTag("Tag 1")));
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
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
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
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
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
    public void determineViolationTypeTest() {
        PolicyCondition policyCondition = new PolicyCondition();
        policyCondition.setSubject(null);
        PolicyEngine policyEngine = new PolicyEngine();
        Assertions.assertNull(policyEngine.determineViolationType(policyCondition.getSubject()));
    }

    @Test
    public void issue1924() {
        Policy policy = qm.createPolicy("Policy 1924", Policy.Operator.ALL, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.SEVERITY, PolicyCondition.Operator.IS, Severity.CRITICAL.name());
        qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.NO_MATCH, "pkg:deb");
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
        Assert.assertEquals(PolicyCondition.Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(1);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.SEVERITY, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(2);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.PACKAGE_URL, policyViolation.getPolicyCondition().getSubject());
    }

    @Test
    public void issue2455() {
        Policy policy = qm.createPolicy("Policy 1924", Policy.Operator.ALL, Policy.ViolationState.INFO);

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
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());

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
        qm.createPolicyCondition(policy, PolicyCondition.Subject.LICENSE_GROUP, PolicyCondition.Operator.IS_NOT, lg.getUuid().toString());

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
        Assert.assertEquals(PolicyCondition.Subject.LICENSE_GROUP, policyViolation.getPolicyCondition().getSubject());
        policyViolation = violations.get(1);
        Assert.assertEquals("Log4J", policyViolation.getComponent().getName());
        Assert.assertEquals(PolicyCondition.Subject.LICENSE_GROUP, policyViolation.getPolicyCondition().getSubject());
    }

    @Test
    public void notificationTest() {
        final var policy = qm.createPolicy("Test", Policy.Operator.ANY, Policy.ViolationState.FAIL);

        // Create a policy condition that matches on any coordinates.
        final var policyConditionA = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, """
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
        assertThat(NOTIFICATIONS).hasSize(1);

        // Create an additional policy condition that matches on the exact version of the component,
        // and re-evaluate policies. Ensure that only one notification per newly violated condition was sent.
        final var policyConditionB = qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.2.3");
        assertThat(policyEngine.evaluate(List.of(component))).hasSize(2);
        assertThat(NOTIFICATIONS).satisfiesExactly(
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
                }
        );

        // Delete a policy condition and re-evaluate policies again. No new notifications should be sent.
        qm.deletePolicyCondition(policyConditionA);
        assertThat(policyEngine.evaluate(List.of(component))).hasSize(1);
        assertThat(NOTIFICATIONS).hasSize(2);
    }

}