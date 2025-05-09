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

import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

class PackageURLPolicyEvaluatorTest extends PersistenceCapableTest {

    private PolicyEvaluator evaluator;

    @BeforeEach
    public void initEvaluator() throws Exception {
        evaluator = new PackageURLPolicyEvaluator();
        evaluator.setQueryManager(qm);
    }

    @Test
    void hasMatch() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void hasMatchNullPurl() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.NO_MATCH, ".+");
        Component component = new Component();
        component.setPurl((PackageURL)null);
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void noMatch() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/acme/web-component@6.9"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void wrongSubject() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void wrongOperator() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.IS, "pkg:generic/acme/example-component@1.0");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void issue1925_matches() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/acme/example-component@1.0?type=jar"));
        component.setPurlCoordinates(new PackageURL("pkg:generic/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void issue1925_no_match() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.NO_MATCH, "pkg:generic/acme/example-component@1.0");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/acme/example-component@1.0?type=jar"));
        component.setPurlCoordinates(new PackageURL("pkg:generic/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void issue2144_existing1() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, "pkg:generic/com/acme/example-component@1.0");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/com/acme/example-component@1.0?type=jar"));
        component.setPurlCoordinates(new PackageURL("pkg:generic/com/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void issue2144_existing2() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, "/com/acme/");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/com/acme/example-component@1.0?type=jar"));
        component.setPurlCoordinates(new PackageURL("pkg:generic/com/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void issue2144_groupIdWithDotMatchesSlash() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, "/com.acme/");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/com/acme/example-component@1.0?type=jar"));
        component.setPurlCoordinates(new PackageURL("pkg:generic/com/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void issue2144_wildcard() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, ".*com.acme.*");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/com/acme/example-component@1.0?type=jar"));
        component.setPurlCoordinates(new PackageURL("pkg:generic/com/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void issue2144_wildcard2() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, ".*acme.*myCompany.*");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/com/acme/example-component@1.0-myCompanyFix-1?type=jar"));
        component.setPurlCoordinates(new PackageURL("pkg:generic/com/acme/example-component@1.0-myCompanyFix-1"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void issue2144_wildcard3() throws Exception {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, ".*(a|b|c)cme.*");
        Component component = new Component();
        component.setPurl(new PackageURL("pkg:generic/com/acme/example-component@1.0?type=jar"));
        component.setPurlCoordinates(new PackageURL("pkg:generic/com/acme/example-component@1.0"));
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }
}
