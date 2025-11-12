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

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class InternalStatusPolicyEvaluatorTest {

    private InternalStatusPolicyEvaluator evaluator;

    @BeforeEach
    void setUp() {
        evaluator = new InternalStatusPolicyEvaluator();
    }

    private Policy policyWith(PolicyCondition condition) {
        Policy policy = new Policy();
        policy.setViolationState(Policy.ViolationState.FAIL);
        policy.addPolicyCondition(condition);
        return policy;
    }

    @Test
    void testIsTrue_NoViolationWhenInternal() {
        Component component = new Component();
        component.setInternal(true);

        PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.IS_INTERNAL);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("true");

        Policy policy = policyWith(condition);
        List<PolicyConditionViolation> result = evaluator.evaluate(policy, component);

        assertTrue(result.isEmpty());
    }

    @Test
    void testIsTrue_ViolationWhenNotInternal() {
        Component component = new Component();
        component.setInternal(false);

        PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.IS_INTERNAL);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("true");

        Policy policy = policyWith(condition);
        List<PolicyConditionViolation> result = evaluator.evaluate(policy, component);

        assertEquals(1, result.size());
    }

    @Test
    void testIsNotTrue_ViolationWhenInternal() {
        Component component = new Component();
        component.setInternal(true);

        PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.IS_INTERNAL);
        condition.setOperator(PolicyCondition.Operator.IS_NOT);
        condition.setValue("true");

        Policy policy = policyWith(condition);
        List<PolicyConditionViolation> result = evaluator.evaluate(policy, component);

        assertEquals(1, result.size());
    }

    @Test
    void testIsNotTrue_NoViolationWhenNotInternal() {
        Component component = new Component();
        component.setInternal(false);

        PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.IS_INTERNAL);
        condition.setOperator(PolicyCondition.Operator.IS_NOT);
        condition.setValue("true");

        Policy policy = policyWith(condition);
        List<PolicyConditionViolation> result = evaluator.evaluate(policy, component);

        assertTrue(result.isEmpty());
    }
}
