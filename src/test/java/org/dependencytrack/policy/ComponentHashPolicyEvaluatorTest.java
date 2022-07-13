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

import java.util.List;

public class ComponentHashPolicyEvaluatorTest extends PersistenceCapableTest {

    PolicyEvaluator evaluator = new ComponentHashPolicyEvaluator();

    @Test
    public void hasMatch() {
        String hashJson = "{ 'algorithm': 'SHA3-512', 'value': 'test_hash' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COMPONENT_HASH, PolicyCondition.Operator.IS, hashJson);
        Component component = new Component();
        component.setName("Test Component");
        component.setSha3_512("test_hash");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assert.assertEquals(component, violation.getComponent());
        Assert.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    public void noMatch() {
        String hashJson = "{ 'algorithm': 'MD5', 'value': 'test_hash' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COMPONENT_HASH, PolicyCondition.Operator.IS, hashJson);
        Component component = new Component();
        component.setName("Example Component");
        component.setSha1("test_hash");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(0, violations.size());
    }

    @Test
    public void NoMatchNoHash() {
        String hashJson = "{ 'algorithm': '', 'value': '' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COMPONENT_HASH, PolicyCondition.Operator.IS, hashJson);
        Component component = new Component();
        component.setName("Example Component");
        component.setSha1("test_hash");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(0, violations.size());
    }
}
