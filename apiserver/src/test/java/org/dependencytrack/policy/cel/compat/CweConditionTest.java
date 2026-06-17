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
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

public class CweConditionTest extends PersistenceCapableTest {
    private static Object[] parameters() {
        return new Object[]{
                new Object[]{Policy.Operator.ANY, Policy.ViolationState.INFO, PolicyCondition.Operator.CONTAINS_ANY,
                        "CWE-123", 123, 0, true, PolicyViolation.Type.SECURITY, Policy.ViolationState.INFO},
                new Object[]{Policy.Operator.ANY, Policy.ViolationState.FAIL, PolicyCondition.Operator.CONTAINS_ALL,
                        "CWE-123, CWE-786", 123, 786, true, PolicyViolation.Type.SECURITY, Policy.ViolationState.FAIL},
                new Object[]{Policy.Operator.ANY, Policy.ViolationState.FAIL, PolicyCondition.Operator.IS,
                        "CWE-123, CWE-786", 123, 786, false, null, null},
                new Object[]{Policy.Operator.ANY, Policy.ViolationState.FAIL, PolicyCondition.Operator.CONTAINS_ALL,
                        "CWE-123.565, CWE-786.67", 123, 786, false, null, null},
        };
    }

    @ParameterizedTest
    @MethodSource("parameters")
    public void testSingleCwe(Policy.Operator policyOperator, Policy.ViolationState violationState,
                              PolicyCondition.Operator conditionOperator, String inputConditionCwe, int inputCweId, int inputCweId2,
                              boolean expectViolation, PolicyViolation.Type actualType, Policy.ViolationState actualViolationState) {
        Policy policy = qm.createPolicy("Test Policy", policyOperator, violationState);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.CWE, conditionOperator, inputConditionCwe);
        final var project = new Project();
        project.setName("acme-app");
        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId("12345");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.addCwe(inputCweId);
        if (inputCweId2 != 0) {
            vulnerability.addCwe(inputCweId2);
        }
        qm.persist(project);
        qm.persist(component);
        qm.persist(vulnerability);
        qm.addVulnerability(vulnerability, component, "internal");
        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getSubject()).isEqualTo(PolicyCondition.Subject.CWE);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getViolationType()).isEqualTo(actualType);
            assertThat(qm.getAllPolicyViolations(component).get(0).getPolicyCondition().getPolicy().getViolationState()).isEqualTo(actualViolationState);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }

}
