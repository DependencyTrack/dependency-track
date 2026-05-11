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
import org.dependencytrack.model.Epss;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.jdbi.EpssDao;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigDecimal;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.model.PolicyCondition.Operator.MATCHES;
import static org.dependencytrack.model.PolicyCondition.Operator.NUMERIC_EQUAL;
import static org.dependencytrack.model.PolicyCondition.Operator.NUMERIC_GREATER_THAN;
import static org.dependencytrack.model.PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL;
import static org.dependencytrack.model.PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL;
import static org.dependencytrack.model.PolicyCondition.Operator.NUMERIC_LESS_THAN;
import static org.dependencytrack.model.PolicyCondition.Operator.NUMERIC_NOT_EQUAL;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

public class EpssConditionTest extends PersistenceCapableTest {

    private static Object[] parameters() {
        return new Object[]{
                // NUMERIC_GREATER_THAN with match.
                new Object[]{NUMERIC_GREATER_THAN, "0.666", 0.667, true},
                // NUMERIC_GREATER_THAN with no match.
                new Object[]{NUMERIC_GREATER_THAN, "0.666", 0.665, false},
                // NUMERIC_GREATER_THAN_OR_EQUAL with match.
                new Object[]{NUMERIC_GREATER_THAN_OR_EQUAL, "0.666", 0.666, true},
                new Object[]{NUMERIC_GREATER_THAN_OR_EQUAL, "0.666", 0.667, true},
                // NUMERIC_GREATER_THAN_OR_EQUAL with no match.
                new Object[]{NUMERIC_GREATER_THAN_OR_EQUAL, "0.666", 0.665, false},
                // NUMERIC_EQUAL with match.
                new Object[]{NUMERIC_EQUAL, "0.666", 0.666, true},
                // NUMERIC_EQUAL with no match.
                new Object[]{NUMERIC_EQUAL, "0.666", 0.667, false},
                // NUMERIC_NOT_EQUAL with match.
                new Object[]{NUMERIC_NOT_EQUAL, "0.666", 0.667, true},
                // NUMERIC_NOT_EQUAL with no match.
                new Object[]{NUMERIC_NOT_EQUAL, "0.666", 0.666, false},
                // NUMERIC_LESSER_THAN_OR_EQUAL with match.
                new Object[]{NUMERIC_LESSER_THAN_OR_EQUAL, "0.666", 0.666, true},
                new Object[]{NUMERIC_LESSER_THAN_OR_EQUAL, "0.666", 0.665, true},
                // NUMERIC_LESSER_THAN_OR_EQUAL with no match.
                new Object[]{NUMERIC_LESSER_THAN_OR_EQUAL, "0.666", 0.667, false},
                // NUMERIC_LESS_THAN with match.
                new Object[]{NUMERIC_LESS_THAN, "0.666", 0.665, true},
                // NUMERIC_LESS_THAN with no match.
                new Object[]{NUMERIC_LESS_THAN, "0.666", 0.667, false},
                // Invalid operator.
                new Object[]{MATCHES, "0.666", 0.666, false},
                // Vulnerability without EPSS score.
                new Object[]{NUMERIC_EQUAL, "0.666", null, false},
                // No condition value.
                new Object[]{NUMERIC_EQUAL, "", 0.666, false},
                // Invalid condition value.
                new Object[]{NUMERIC_EQUAL, "foo", 0.666, false},
        };
    }

    @ParameterizedTest
    @MethodSource("parameters")
    public void evaluateTest(
            final Operator operator,
            final String conditionValue,
            final Double vulnEpssScore,
            final boolean expectViolation
    ) {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.EPSS, operator, conditionValue);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-123");
        vuln.setSource(Vulnerability.Source.NVD);
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");

        useJdbiHandle(handle -> handle.attach(EpssDao.class)
                .createOrUpdateAll(List.of(new Epss(
                        "CVE-123",
                        vulnEpssScore != null ? BigDecimal.valueOf(vulnEpssScore) : null,
                        null))));

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }

}
