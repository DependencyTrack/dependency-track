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
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation.Type;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

public class HashConditionTest extends PersistenceCapableTest {

    private static Object[] parameters() {
        return new Object[]{
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ \"algorithm\": \"SHA256\", \"value\": \"test_hash\" }",
                        "test_hash", true, ViolationState.FAIL, Type.OPERATIONAL, ViolationState.FAIL},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ \"algorithm\": \"SHA256\", \"value\": \"test_hash\" }",
                        "test_hash", true, ViolationState.WARN, Type.OPERATIONAL, ViolationState.WARN},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ \"algorithm\": \"SHA256\", \"value\": \"test_hash\" }",
                        "test_hash_false", false, ViolationState.INFO, Type.OPERATIONAL, ViolationState.INFO},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ \"algorithm\": \"test\", \"value\": \"test_hash\" }",
                        "test_hash", false, ViolationState.INFO, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS_NOT, "{ \"algorithm\": \"SHA256\", \"value\": \"test_hash\" }",
                        "test_hash20", true, ViolationState.FAIL, Type.OPERATIONAL, ViolationState.FAIL},
                new Object[]{Policy.Operator.ANY, Operator.IS_NOT, "{ \"algorithm\": \"SHA256\", \"value\": \"test_hash\" }",
                        "test_hash", false, ViolationState.INFO, null, null},
                new Object[]{Policy.Operator.ANY, Operator.MATCHES, "{ \"algorithm\": \"SHA256\", \"value\": \"test_hash\" }",
                        "test_hash", false, ViolationState.INFO, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ \"algorithm\": null, \"value\": \"test_hash\" }",
                        "test_hash", false, ViolationState.FAIL, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ \"algorithm\": \"MD5\", \"value\": null }",
                        "test_hash", false, ViolationState.FAIL, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ \"algorithm\": \"SHA256\", \"value\": \"\" }",
                        "test_hash", false, ViolationState.FAIL, null, null},
                new Object[]{Policy.Operator.ANY, Operator.IS, "{ \"algorithm\": \"\", \"value\": \"test_hash\" }",
                        "test_hash", false, ViolationState.FAIL, null, null},
        };
    }

    @ParameterizedTest
    @MethodSource("parameters")
    public void testCondition(Policy.Operator policyOperator, final Operator condition, final String conditionHash,
                              final String actualHash, final boolean expectViolation, ViolationState violationState,
                              Type actualType, ViolationState actualViolationState) {
        final Policy policy = qm.createPolicy("policy", policyOperator, violationState);
        qm.createPolicyCondition(policy, Subject.COMPONENT_HASH, condition, conditionHash);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setSha256(actualHash);
        qm.persist(component);


        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getViolationType()).isEqualTo(actualType);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getPolicy().getViolationState()).isEqualTo(actualViolationState);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }


    @Test
    public void testWithNullPolicyCondition() {

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setSha256("actualHash");
        qm.persist(component);
        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).isEmpty();
    }

}
