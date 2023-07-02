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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class VersionDistancePolicyEvaluatorTest extends PersistenceCapableTest {

    @Parameterized.Parameters(name = "[{index}] version={0} latestVersion={1} operator={2} distance={3} shouldViolate={4}")
    public static Collection<?> testParameters() {
        return Arrays.asList(new Object[][]{
            {"1.0.0", "1.0.0", Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"1.0.0", "1.0.0", Operator.NUMERIC_GREATER_THAN, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            // Latest version is 1 minor newer than current version
            {"1.2.3", "1.3.1", Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "{ \"major\": \"0\", \"minor\": \"1\", \"patch\": \"?\" }", true},
            {"1.2.3", "1.3.1", Operator.NUMERIC_GREATER_THAN, "{ \"major\": \"0\", \"minor\": \"1\", \"patch\": \"?\" }", false},
            {"1.2.3", "1.3.1", Operator.NUMERIC_EQUAL, "{ \"major\": \"0\", \"minor\": \"1\", \"patch\": \"?\" }", true},
            {"1.2.3", "1.3.1", Operator.NUMERIC_NOT_EQUAL, "{ \"major\": \"0\", \"minor\": \"1\", \"patch\": \"?\" }", false},
            {"1.2.3", "1.3.1", Operator.NUMERIC_LESS_THAN, "{ \"major\": \"0\", \"minor\": \"1\", \"patch\": \"?\" }", false},
            {"1.2.3", "1.3.1", Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "{ \"major\": \"0\", \"minor\": \"1\", \"patch\": \"?\" }", true},
            // Latest version is 1 major newer than current version
            {"1.2.3", "2.1.1", Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"1.2.3", "2.1.1", Operator.NUMERIC_GREATER_THAN, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"1.2.3", "2.1.1", Operator.NUMERIC_EQUAL, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"1.2.3", "2.1.1", Operator.NUMERIC_NOT_EQUAL, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"1.2.3", "2.1.1", Operator.NUMERIC_LESS_THAN, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"1.2.3", "2.1.1", Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            // Latest version is 2 major newer than current version
            {"1.2.3", "3.0.1", Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "{ \"major\": \"2\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"1.2.3", "3.0.1", Operator.NUMERIC_GREATER_THAN, "{ \"major\": \"2\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"1.2.3", "3.0.1", Operator.NUMERIC_EQUAL, "{ \"major\": \"2\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"1.2.3", "3.0.1", Operator.NUMERIC_NOT_EQUAL, "{ \"major\": \"2\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"1.2.3", "3.0.1", Operator.NUMERIC_LESS_THAN, "{ \"major\": \"2\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"1.2.3", "3.0.1", Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "{ \"major\": \"2\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            // Component is latest version.
            {"1.2.3", "1.2.3", Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "{ \"major\": \"0\", \"minor\": \"0\", \"patch\": \"0\" }", true},
            {"1.2.3", "1.2.3", Operator.NUMERIC_GREATER_THAN, "{ \"major\": \"0\", \"minor\": \"0\", \"patch\": \"0\" }", false},
            {"1.2.3", "1.2.3", Operator.NUMERIC_EQUAL, "{ \"major\": \"0\", \"minor\": \"0\", \"patch\": \"0\" }", true},
            {"1.2.3", "1.2.3", Operator.NUMERIC_NOT_EQUAL, "{ \"major\": \"0\", \"minor\": \"0\", \"patch\": \"0\" }", false},
            {"1.2.3", "1.2.3", Operator.NUMERIC_LESS_THAN, "{ \"major\": \"0\", \"minor\": \"0\", \"patch\": \"0\" }", false},
            {"1.2.3", "1.2.3", Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "{ \"major\": \"0\", \"minor\": \"0\", \"patch\": \"0\" }", true},
            // Negative distanse.
            {"2.3.4", "1.2.3", Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"2.3.4", "1.2.3", Operator.NUMERIC_GREATER_THAN, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"2.3.4", "1.2.3", Operator.NUMERIC_EQUAL, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"2.3.4", "1.2.3", Operator.NUMERIC_NOT_EQUAL, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"2.3.4", "1.2.3", Operator.NUMERIC_LESS_THAN, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"2.3.4", "1.2.3", Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            // Combined policies.
            {"2.0.0", "1.0.0", Operator.NUMERIC_EQUAL, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"1:1.0.0", "1.0.0", Operator.NUMERIC_EQUAL, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"1:2.0.0", "1.0.0", Operator.NUMERIC_EQUAL, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"1.0.0", "1.0.0", Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"1.0.0", "1.0.0", Operator.NUMERIC_LESS_THAN, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", true},
            {"1.0.0", "1.0.0", Operator.NUMERIC_EQUAL, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"1.0.0", "1.0.0", Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"1.0.0", "1.0.0", Operator.NUMERIC_GREATER_THAN, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"2:2.0.0", "1.0.0", Operator.NUMERIC_EQUAL, "{\"epoch\": \"1\", \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            {"3.2.2", "1.0.0", Operator.NUMERIC_EQUAL, "{\"epoch\": \"0\", \"major\": \"1\", \"minor\": \"1\", \"patch\": \"1\" }", false},
            {"1.2.2", "1.0.0", Operator.NUMERIC_EQUAL, "{\"epoch\": \"0\", \"major\": \"0\", \"minor\": \"1\", \"patch\": \"1\" }", false},
            {"0.2.2", "1.0.0", Operator.NUMERIC_EQUAL, "{\"epoch\": \"0\", \"major\": \"0\", \"minor\": \"1\", \"patch\": \"1\" }", false},
            // Unsupported operator.
            {"1.2.3", "2.1.1", Operator.MATCHES, "{ \"major\": \"1\", \"minor\": \"?\", \"patch\": \"?\" }", false},
            // Invalid distanse format.
            {"1.2.3", "2.1.1", Operator.NUMERIC_EQUAL, "{ \"major\": \"1a\" }", false},
            // No known latestVersion.
            {"1.2.3", null, Operator.NUMERIC_EQUAL, "{ \"major\": \"0\", \"minor\": \"0\", \"patch\": \"0\" }", false},
        });
    }

    private final String version;
    private final String latestVersion;
    private final Operator operator;
    private final String versionDistance;
    private final boolean shouldViolate;

    public VersionDistancePolicyEvaluatorTest(final String version, String latestVersion,
            Operator operator, String versionDistance, boolean shouldViolate) {
        this.version = version;
        this.latestVersion = latestVersion;
        this.operator = operator;
        this.versionDistance = versionDistance;
        this.shouldViolate = shouldViolate;
    }

    @Test
    public void evaluateTest() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final var condition = qm.createPolicyCondition(policy, Subject.VERSION_DISTANCE, operator, versionDistance);

        final var project = new Project();
        project.setName("name");
        project.setActive(true);

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("foo");
        metaComponent.setName("bar");
        metaComponent.setLatestVersion("6.6.6");
        if (latestVersion != null) {
            metaComponent.setLatestVersion(latestVersion);
        }
        metaComponent.setLastCheck(new Date());
        qm.persist(metaComponent);

        final var component = new Component();
        component.setProject(project);
        component.setGroup("foo");
        component.setName("bar");
        component.setPurl("pkg:maven/foo/bar@" + version);
        component.setVersion(version);
        qm.persist(component);

        project.setDirectDependencies("[{\"uuid\":\""+component.getUuid()+"\"}]");
        qm.persist(project);

        final var evaluator = new VersionDistancePolicyEvaluator();
        evaluator.setQueryManager(qm);

        final List<PolicyConditionViolation> violations = evaluator.evaluate(policy, component);
        if (shouldViolate) {
            assertThat(violations).hasSize(1);
            final PolicyConditionViolation violation = violations.get(0);
            assertThat(violation.getComponent()).isEqualTo(component);
            assertThat(violation.getPolicyCondition()).isEqualTo(condition);
        } else {
            assertThat(violations).isEmpty();
        }
    }

}