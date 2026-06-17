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
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

public class VersionConditionTest extends PersistenceCapableTest {

    private static Object[] parameters() {
        return new Object[]{
                // MATCHES with exact match
                new Object[]{PolicyCondition.Operator.NUMERIC_EQUAL, "v1.2.3", "v1.2.3", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_EQUAL, "v1.2.3", "v1.2.4", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "0.4.5-SNAPSHOT", "0.4.5", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_NOT_EQUAL, "0.4.5", "0.4.5", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN, "0.4.5", "0.5.5", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN, "0.4.4", "0.4.4", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "0.4.4", "0.4.4", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "v0.4.5-SNAPSHOT", "z0.4.5", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "v0.4.5-SNAPSHOT", "0.4.5", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "v0.4.*", "v0.4.1", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_LESS_THAN, "v0.4.*", "v0.4.1", false},
                new Object[]{PolicyCondition.Operator.NUMERIC_LESS_THAN, "v0.4.*", "v0.3.1", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "v0.4.*", "v0.4.0", true},
                new Object[]{PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "v0.4.*", "v0.4.2", false},
        };
    }

    @ParameterizedTest
    @MethodSource("parameters")
    public void testCondition(final PolicyCondition.Operator operator, final String conditionVersion, final String componentVersion, final boolean expectViolation) {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, operator, conditionVersion);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion(componentVersion);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }
}
