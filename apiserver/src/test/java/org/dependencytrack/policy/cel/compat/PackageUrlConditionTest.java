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

import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PackageUrlConditionTest extends PersistenceCapableTest {

    private static Object[] parameters() {
        return new Object[]{
                //Matches with exact match
                new Object[]{PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/example-component@1.0", true},
                //matching on null purl - invalid. We cannot pass null for purl
                //new Object[]{PolicyCondition.Operator.NO_MATCH, ".+", "", true},
                //No Match exact
                new Object[]{PolicyCondition.Operator.NO_MATCH, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/web-component@6.9", true},
                //Wrong operator
                new Object[]{PolicyCondition.Operator.IS, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/example-component@1.0", false},
                //Exact match
                new Object[]{PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/example-component@1.0", true},
                //Matches with qualifier also
                new Object[]{PolicyCondition.Operator.MATCHES, "pkg:generic/acme/example-component@1.0", "pkg:generic/acme/example-component@1.0?type=jar", true},
                //Partial match
                new Object[]{PolicyCondition.Operator.MATCHES, "/com/acme/", "pkg:generic/com/acme/example-component@1.0?type=jar", true},
                //Partial match
                new Object[]{PolicyCondition.Operator.MATCHES, "/com.acme/", "pkg:generic/com/acme/example-component@1.0?type=jar", true},
                //Matches on wild card
                new Object[]{PolicyCondition.Operator.MATCHES, ".*com.acme.*", "pkg:generic/com/acme/example-component@1.0?type=jar", true},
                //Matches on wild card
                new Object[]{PolicyCondition.Operator.MATCHES, ".*acme.*myCompany.*", "pkg:generic/com/acme/example-component@1.0-myCompanyFix-1?type=jar", true},
                //Matches on wild card
                new Object[]{PolicyCondition.Operator.MATCHES, ".*(a|b|c)cme.*", "pkg:generic/com/acme/example-component@1.0?type=jar", true},
        };
    }

    @ParameterizedTest
    @MethodSource("parameters")
    public void testCondition(final PolicyCondition.Operator operator, final String conditionPurl, final String componentPurl, final boolean expectViolation) throws Exception{
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.PACKAGE_URL, operator, conditionPurl);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setPurl(new PackageURL(componentPurl));
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            List<PolicyViolation> violations = qm.getAllPolicyViolations(component);
            assertThat(violations).hasSize(1);
            PolicyViolation violation = violations.get(0);
            assertEquals(component, violation.getComponent());
            assertEquals(condition, violation.getPolicyCondition());
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }

}
