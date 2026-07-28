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
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;

public class SeverityConditionTest extends PersistenceCapableTest {

    private static Object[] parameters() {
        return new Object[]{
                // IS with exact match
                new Object[]{Operator.IS, "CRITICAL", "CRITICAL", true},
                // IS with regex match (regex is not supported by this condition)
                new Object[]{Operator.IS, "CRI[A-Z]+", "CRITICAL", false},
                // IS with no match
                new Object[]{Operator.IS, "CRITICAL", "LOW", false},
                // IS_NOT with no match
                new Object[]{Operator.IS_NOT, "CRITICAL", "LOW", true},
                // IS_NOT with exact match
                new Object[]{Operator.IS_NOT, "UNASSIGNED", "UNASSIGNED", false},
                // IS with quotes (actualSeverity can't have quotes because it's an enum)
                new Object[]{Operator.IS, "\"CRITICAL", "CRITICAL", false}
        };
    }

    @ParameterizedTest
    @MethodSource("parameters")
    public void testCondition(final Operator operator, final String conditionSeverity, final String actualSeverity, final boolean expectViolation) {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, ViolationState.INFO);
        qm.createPolicyCondition(policy, Subject.SEVERITY, operator, conditionSeverity);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var vulnA = new Vulnerability();
        vulnA.setVulnId("INT-123");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        vulnA.setSeverity(Severity.valueOf(actualSeverity));
        qm.persist(vulnA);

        final var vulnB = new Vulnerability();
        vulnB.setVulnId("INT-666");
        vulnB.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vulnB);

        qm.addVulnerability(vulnA, component, "internal");
        qm.addVulnerability(vulnB, component, "internal");

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }

    @Test
    public void testSeverityCalculation() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, ViolationState.FAIL);
        qm.createPolicyCondition(policy, Subject.SEVERITY, Operator.IS, Severity.CRITICAL.name(), Type.SECURITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        // Create a vulnerability that has all scores (CVSSv2, CVSSv3, OWASP RR)
        // available, but no severity is set explicitly.
        //
        // Even though the expression only accesses the `severity` field, the policy
        // engine should fetch all scores in order to derive the severity from them.
        // Note that when multiple scores are available, the highest severity wins.
        //
        // The highest severity among the scores below is CRITICAL from CVSSv3.

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-123");
        vuln.setSource(Vulnerability.Source.NVD);
        // vuln.setSeverity(Severity.INFO);
        vuln.setCvssV2BaseScore(BigDecimal.valueOf(6.0));
        vuln.setCvssV2ImpactSubScore(BigDecimal.valueOf(6.4));
        vuln.setCvssV2ExploitabilitySubScore(BigDecimal.valueOf(6.8));
        vuln.setCvssV2Vector("(AV:N/AC:M/Au:S/C:P/I:P/A:P)");
        vuln.setCvssV3BaseScore(BigDecimal.valueOf(9.1));
        vuln.setCvssV3ImpactSubScore(BigDecimal.valueOf(5.3));
        vuln.setCvssV3ExploitabilitySubScore(BigDecimal.valueOf(3.1));
        vuln.setCvssV3Vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L");
        vuln.setOwaspRRLikelihoodScore(BigDecimal.valueOf(4.5));
        vuln.setOwaspRRTechnicalImpactScore(BigDecimal.valueOf(5.0));
        vuln.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(3.75));
        vuln.setOwaspRRVector("(SL:5/M:5/O:2/S:9/ED:4/EE:2/A:7/ID:2/LC:2/LI:2/LAV:7/LAC:9/FD:3/RD:5/NC:0/PV:7)");
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");

        new CelPolicyEngine().evaluateProject(project.getUuid());
        assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
    }

}
