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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.*;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;
public class PolicyEngineTest extends PersistenceCapableTest {

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
}
