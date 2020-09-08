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

public class CpePolicyEvaluatorTest extends PersistenceCapableTest {

    @Test
    public void hasMatch() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.CPE, PolicyCondition.Operator.MATCHES, "cpe:/a:acme:application:1.0.0");
        Component component = new Component();
        component.setCpe("cpe:/a:acme:application:1.0.0");
        PolicyEvaluator evaluator = new CpePolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertTrue(optional.isPresent());
        PolicyConditionViolation violation = optional.get();
        Assert.assertEquals(component, violation.getComponent());
        Assert.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    public void noMatch() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.CPE, PolicyCondition.Operator.MATCHES, "cpe:/a:acme:application:1.0.0");
        Component component = new Component();
        component.setCpe("cpe:/a:acme:application:2.0.0");
        PolicyEvaluator evaluator = new CpePolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

    @Test
    public void wrongSubject() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "cpe:/a:acme:application:1.0.0");
        Component component = new Component();
        component.setCpe("cpe:/a:acme:application:1.0.0");
        PolicyEvaluator evaluator = new CpePolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

    @Test
    public void wrongOperator() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.CPE, PolicyCondition.Operator.IS, "cpe:/a:acme:application:1.0.0");
        Component component = new Component();
        component.setCpe("cpe:/a:acme:application:1.0.0");
        PolicyEvaluator evaluator = new CpePolicyEvaluator();
        Optional<PolicyConditionViolation> optional = evaluator.evaluate(policy, component);
        Assert.assertFalse(optional.isPresent());
    }

}
