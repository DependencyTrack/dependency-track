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

import java.math.BigDecimal;
import java.util.List;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Assert;
import org.junit.Test;

public class EpssPolicyEvaluatorTest extends PersistenceCapableTest {
    CwePolicyEvaluator cwePolicyEvaluator = new CwePolicyEvaluator();

    @Test
    public void hasMatch() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.EPSS, PolicyCondition.Operator.NUMERIC_LESS_THAN, "0.99");
        Project project = new Project();
        project.setName("My Project");
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0");
        component.setProject(project);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setEpssScore(BigDecimal.valueOf(0.33));
        qm.persist(project);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        PolicyEvaluator evaluator = new EpssPolicyEvaluator();
        evaluator.setQueryManager(qm);
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assert.assertEquals(component.getId(), violation.getComponent().getId());
        Assert.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    public void wrongOperator() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EPSS, PolicyCondition.Operator.MATCHES, "0.99");
        Project project = new Project();
        project.setName("My Project");
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0");
        component.setProject(project);
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setEpssScore(BigDecimal.valueOf(0.33));
        qm.persist(project);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, AnalyzerIdentity.INTERNAL_ANALYZER);
        PolicyEvaluator evaluator = new EpssPolicyEvaluator();
        evaluator.setQueryManager(qm);
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(0, violations.size());
    }
}
