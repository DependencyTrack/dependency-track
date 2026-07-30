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
import org.dependencytrack.model.Scope;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

public class ComponentScopeCelPolicyTest extends PersistenceCapableTest {
    private static Object[] parameters() {
        return new Object[]{
                // IS with exact match
                new Object[]{PolicyCondition.Operator.IS, "REQUIRED", "REQUIRED", true},
                // IS with no match
                new Object[]{PolicyCondition.Operator.IS, "REQUIRED", "OPTIONAL", false},
                // IS_NOT with match
                new Object[]{PolicyCondition.Operator.IS_NOT, "EXCLUDED", "OPTIONAL", true},
                // IS_NOT with no match
                new Object[]{PolicyCondition.Operator.IS_NOT, "EXCLUDED", "EXCLUDED", false},
                // IS with exact match when the actual scope is unassigned
                new Object[]{PolicyCondition.Operator.IS, "UNASSIGNED", null, true},
                // IS with no match when the actual scope is unassigned
                new Object[]{PolicyCondition.Operator.IS, "REQUIRED", null, false},
                // IS_NOT with exact match when the actual scope is unassigned
                new Object[]{PolicyCondition.Operator.IS_NOT, "REQUIRED", null, true},
                // IS_NOT with no match when the actual scope is unassigned
                new Object[]{PolicyCondition.Operator.IS, "UNASSIGNED", null, true},
                // IS with quotes (scope can't have quotes because it's an enum)
                new Object[]{PolicyCondition.Operator.IS, "\"REQUIRED", "REQUIRED", false}
        };
    }

    @ParameterizedTest
    @MethodSource("parameters")
    public void testCondition(final PolicyCondition.Operator operator, final String conditionScope, final String actualScope, final boolean expectViolation) {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COMPONENT_SCOPE, operator, conditionScope);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setScope(actualScope == null ? null : Scope.valueOf(actualScope));
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }
}
