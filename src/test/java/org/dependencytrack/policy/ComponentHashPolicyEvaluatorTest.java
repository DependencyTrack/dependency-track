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

/*
 * Logic Explanation:
 * TEST                         OPERATOR         POLICY HASH	COMPONENT HASH	OUTCOME	        EXPLANATION
 * testIsConditionWithMatch     IS	             da39...709	    da39...709	    Violation	    Hashes match, violation. (1)
 * testIsConditionNoMatch       IS	             da39...709	    abcd...f12	    No Violation	Hashes differ, no violation. (0)
 * testIsNotConditionWithMatch  IS_NOT	         da39...709	    da39...709	    No Violation	Hashes match, no violation. (0)
 * testIsNotConditionNoMatch    IS_NOT	         da39...709	    abcd...f12	    Violation	    Hashes differ, violation. (1)
 */
package org.dependencytrack.policy;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

public class ComponentHashPolicyEvaluatorTest {

    private ComponentHashPolicyEvaluator evaluator;

    @Before
    public void initEvaluator() {
        evaluator = new ComponentHashPolicyEvaluator();
    }

    @Test
    public void testIsConditionWithMatch() {
        String hashJson = "{ 'algorithm': 'SHA-1', 'value': 'da39a3ee5e6b4b0d3255bfef95601890afd80709' }";
        Policy policy = new Policy();
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.FAIL);

        PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.COMPONENT_HASH);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue(hashJson);
        policy.addPolicyCondition(condition);

        Component component = new Component();
        component.setSha1("da39a3ee5e6b4b0d3255bfef95601890afd80709");

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(1, violations.size()); // No violation expected
    }

    @Test
    public void testIsConditionNoMatch() {
        String hashJson = "{ 'algorithm': 'SHA-1', 'value': 'da39a3ee5e6b4b0d3255bfef95601890afd80709' }";
        Policy policy = new Policy();
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.FAIL);

        PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.COMPONENT_HASH);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue(hashJson);
        policy.addPolicyCondition(condition);

        Component component = new Component();
        component.setSha1("abcdef1234567890abcdef1234567890abcdef12");

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(0, violations.size()); //  Violation expected
    }

    @Test
    public void testIsNotConditionWithMatch() {
        String hashJson = "{ 'algorithm': 'SHA-1', 'value': 'da39a3ee5e6b4b0d3255bfef95601890afd80709' }";
        Policy policy = new Policy();
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.FAIL);

        PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.COMPONENT_HASH);
        condition.setOperator(PolicyCondition.Operator.IS_NOT);
        condition.setValue(hashJson);
        policy.addPolicyCondition(condition);

        Component component = new Component();
        component.setSha1("da39a3ee5e6b4b0d3255bfef95601890afd80709");

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(0, violations.size()); //  Violation expected
    }

    @Test
    public void testIsNotConditionNoMatch() {
        String hashJson = "{ 'algorithm': 'SHA-1', 'value': 'da39a3ee5e6b4b0d3255bfef95601890afd80709' }";
        Policy policy = new Policy();
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.FAIL);

        PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.COMPONENT_HASH);
        condition.setOperator(PolicyCondition.Operator.IS_NOT);
        condition.setValue(hashJson);
        policy.addPolicyCondition(condition);

        Component component = new Component();
        component.setSha1("abcdef1234567890abcdef1234567890abcdef12");

        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assert.assertEquals(1, violations.size()); // No violation expected
    }
}