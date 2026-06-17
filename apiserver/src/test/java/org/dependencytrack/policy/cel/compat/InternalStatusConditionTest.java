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
package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Policy.ViolationState;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class InternalStatusConditionTest extends PersistenceCapableTest {

    @ParameterizedTest
    @CsvSource({
            // IS true matches an internal component
            "IS, true, true, true",
            // IS true does not match a non-internal component
            "IS, true, false, false",
            // IS false matches a non-internal component
            "IS, false, false, true",
            // IS_NOT true matches a non-internal component
            "IS_NOT, true, false, true",
            // IS_NOT true does not match an internal component
            "IS_NOT, true, true, false",
            // Non-boolean values are parsed as false by Boolean.parseBoolean
            "IS, notABoolean, false, true",
            "IS, notABoolean, true, false"
    })
    void shouldEvaluateInternalStatusCondition(
            Operator operator,
            String conditionValue,
            boolean componentInternal,
            boolean expectViolation) {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, ViolationState.INFO);
        qm.createPolicyCondition(policy, Subject.IS_INTERNAL, operator, conditionValue);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setInternal(componentInternal);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }

    @Test
    void shouldBuildScriptSourceForIsOperator() {
        final var condition = new PolicyCondition();
        condition.setOperator(Operator.IS);
        condition.setValue("true");

        assertThat(new InternalStatusCelPolicyScriptSourceBuilder().apply(condition))
                .isEqualTo("component.is_internal == true");
    }

    @Test
    void shouldBuildScriptSourceForIsNotOperator() {
        final var condition = new PolicyCondition();
        condition.setOperator(Operator.IS_NOT);
        condition.setValue("false");

        assertThat(new InternalStatusCelPolicyScriptSourceBuilder().apply(condition))
                .isEqualTo("component.is_internal != false");
    }

    @ParameterizedTest
    @EnumSource(value = Operator.class, names = {"IS", "IS_NOT"}, mode = EnumSource.Mode.EXCLUDE)
    void shouldReturnNullForUnsupportedOperator(final Operator operator) {
        final var condition = new PolicyCondition();
        condition.setOperator(operator);
        condition.setValue("true");

        assertThat(new InternalStatusCelPolicyScriptSourceBuilder().apply(condition)).isNull();
    }

}
