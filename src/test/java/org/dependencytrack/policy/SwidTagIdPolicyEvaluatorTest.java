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

public class SwidTagIdPolicyEvaluatorTest extends PersistenceCapableTest {

    @Test
    public void hasMatch() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.SWID_TAGID, PolicyCondition.Operator.MATCHES, "0123456789");
        Component component = new Component();
        component.setSwidTagId("0123456789");
        PolicyEvaluator evaluator = new SwidTagIdPolicyEvaluator();
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assert.assertEquals(component, violation.getComponent());
        Assert.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    public void noMatch() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.SWID_TAGID, PolicyCondition.Operator.MATCHES, "0123456789");
        Component component = new Component();
        component.setSwidTagId("0000000000");
        PolicyEvaluator evaluator = new SwidTagIdPolicyEvaluator();
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(0, violations.size());
    }

    @Test
    public void wrongSubject() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "0123456789");
        Component component = new Component();
        component.setSwidTagId("0123456789");
        PolicyEvaluator evaluator = new SwidTagIdPolicyEvaluator();
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(0, violations.size());
    }

    @Test
    public void wrongOperator() {
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.SWID_TAGID, PolicyCondition.Operator.IS, "0123456789");
        Component component = new Component();
        component.setSwidTagId("0123456789");
        PolicyEvaluator evaluator = new SwidTagIdPolicyEvaluator();
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(0, violations.size());
    }

}
