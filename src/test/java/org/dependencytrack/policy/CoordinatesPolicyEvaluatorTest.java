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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.junit.Assert;
import org.junit.Test;
import java.util.Optional;

public class CoordinatesPolicyEvaluatorTest extends PersistenceCapableTest {

    @Test
    public void hasFullMatch() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setVersion("1.0.0");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertTrue(optional.isPresent());
        PolicyConditionViolation violation = optional.get();
        Assert.assertEquals(component, violation.getComponent());
        Assert.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    public void hasMatchWithoutGroup() {
        String def = "{ 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0.0");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertTrue(optional.isPresent());
        PolicyConditionViolation violation = optional.get();
        Assert.assertEquals(component, violation.getComponent());
        Assert.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    public void hasWildcardMatch() {
        String def = "{ 'group': '*', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Anything here");
        component.setName("Test Component");
        component.setVersion("1.0.0");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertTrue(optional.isPresent());
        PolicyConditionViolation violation = optional.get();
        Assert.assertEquals(component, violation.getComponent());
        Assert.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    public void hasPartialMatch1() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setVersion("2.0.0");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

    @Test
    public void hasPartialMatch2() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Acme");
        component.setName("Test");
        component.setVersion("1.0.0");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

    @Test
    public void hasPartialMatch3() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Example");
        component.setName("Test Component");
        component.setVersion("1.0.0");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

    @Test
    public void hasPartialMatch4() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0.0");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

    @Test
    public void noMatch() {
        String def = "{ 'name': 'Test Component' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setName("Example Component");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

    @Test
    public void wrongSubject() {
        String def = "{ 'name': 'Test Component' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setName("Test Component");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

    @Test
    public void wrongOperator() {
        String def = "{ 'name': 'Test Component' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.IS, def);
        Component component = new Component();
        component.setName("Test Component");
        PolicyEvaluator evaluator = new CoordinatesPolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

}
