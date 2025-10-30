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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

class CoordinatesPolicyEvaluatorTest extends PersistenceCapableTest {

    private PolicyEvaluator evaluator;

    @BeforeEach
    public void initEvaluator() throws Exception {
        evaluator = new CoordinatesPolicyEvaluator();
        evaluator.setQueryManager(qm);
    }

    @Test
    void hasFullMatch() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setVersion("1.0.0");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void hasMatchWithoutGroup() {
        String def = "{ 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0.0");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void hasWildcardMatch() {
        String def = "{ 'group': '*', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Anything here");
        component.setName("Test Component");
        component.setVersion("1.0.0");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
        PolicyConditionViolation violation = violations.get(0);
        Assertions.assertEquals(component, violation.getComponent());
        Assertions.assertEquals(condition, violation.getPolicyCondition());
    }

    @Test
    void hasPartialMatch1() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setVersion("2.0.0");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void hasPartialMatch2() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Acme");
        component.setName("Test");
        component.setVersion("1.0.0");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void hasPartialMatch3() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setGroup("Example");
        component.setName("Test Component");
        component.setVersion("1.0.0");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void hasPartialMatch4() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setName("Test Component");
        component.setVersion("1.0.0");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void noMatch() {
        String def = "{ 'name': 'Test Component' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setName("Example Component");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void wrongSubject() {
        String def = "{ 'name': 'Test Component' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, PolicyCondition.Operator.MATCHES, def);
        Component component = new Component();
        component.setName("Test Component");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void wrongOperator() {
        String def = "{ 'name': 'Test Component' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.IS, def);
        Component component = new Component();
        component.setName("Test Component");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void matchWithComponentVersionAndConditionVersionNull() {
        final String def = "{}";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);

        final var component = new Component();

        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

    @Test
    void noMatchWithConditionVersionNull() {
        final String def = "{}";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);

        final var component = new Component();
        component.setVersion("1.0.0");

        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void matchWithVersionOperatorLessThan() {
        final String def = "{ 'version': '< 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void noMatchWithVersionOperatorLessThan() {
        final String def = "{ 'version': '< 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.NO_MATCH, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

    @Test
    void matchWithVersionOperatorLessThanOrEqual() {
        final String def = "{ 'version': '<= 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void noMatchWithVersionOperatorLessThanOrEqual() {
        final String def = "{ 'version': '<= 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.NO_MATCH, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

    @Test
    void matchWithVersionOperatorEqual() {
        final String def = "{ 'version': '== 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void noMatchWithVersionOperatorEqual() {
        final String def = "{ 'version': '== 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.NO_MATCH, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

    @Test
    void matchWithVersionOperatorNotEqual() {
        final String def = "{ 'version': '!= 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

    @Test
    void noMatchWithVersionOperatorNotEqual() {
        final String def = "{ 'version': '!= 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.NO_MATCH, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void matchWithVersionOperatorGreaterThan() {
        final String def = "{ 'version': '> 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

    @Test
    void noMatchWithVersionOperatorGreaterThan() {
        final String def = "{ 'version': '> 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.NO_MATCH, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void matchWithVersionOperatorGreaterThanOrEqual() {
        final String def = "{ 'version': '>= 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());
    }

    @Test
    void noMatchWithVersionOperatorGreaterThanOrEqual() {
        final String def = "{ 'version': '>= 1.1.1' }";
        final var policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.NO_MATCH, def);

        final var component = new Component();

        // Component version is lower
        component.setVersion("1.1.0");
        Assertions.assertEquals(1, evaluator.evaluate(policy, component).size());

        // Component version is equal
        component.setVersion("1.1.1");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());

        // Component version is higher
        component.setVersion("1.1.2");
        Assertions.assertEquals(0, evaluator.evaluate(policy, component).size());
    }

    @Test
    void noMatchWithInvertedMatch() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.NO_MATCH, def);
        Component component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setVersion("1.0.0");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(0, violations.size());
    }

    @Test
    void matchWithInvertedMatch() {
        String def = "{ 'group': 'Acme', 'name': 'Test Component', 'version': '1.0.0' }";
        Policy policy = qm.createPolicy("Test Policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.NO_MATCH, def);
        Component component = new Component();
        component.setGroup("Acme");
        component.setName("Test Component");
        component.setVersion("2.0.0");
        List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        Assertions.assertEquals(1, violations.size());
    }
}
