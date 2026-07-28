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

import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Project;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

public class CoordinatesConditionTest extends PersistenceCapableTest {
    private static Object[] parameters() {
        return new Object[]{
                //MATCHES group regex
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme*\", \"name\": \"acme*\", \"version\": \">=v1.2*\"}", "{\"group\": \"acme-app\", \"name\": \"acme-lib\", \"version\": \"v1.2.3\"}", true},
                //Exact matches
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme-app\", \"name\": \"acme-lib\", \"version\": \"v1.2.3\"}", "{\"group\": \"acme-app\", \"name\": \"acme-lib\", \"version\": \"v1.2.3\"}", true},
                //Exact group does not match
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"org.hippo\", \"name\": \"acme-lib\", \"version\": \"v1.2.3\"}", "{\"group\": \"acme-app\", \"name\": \"acme-lib\", \"version\": \"v1.2.3\"}", false},
                //Name does not match regex
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme-app\", \"name\": \"*acme-lib*\", \"version\": \"v1.2.3\"}", "{\"group\": \"acme-app\", \"name\": \"good-foo-lib\", \"version\": \"v1.2.3\"}", false},
                //Version regex does not match
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme-app\", \"name\": \"*acme-lib*\", \"version\": \"v1.*\"}", "{\"group\": \"acme-app\", \"name\": \"acme-lib\", \"version\": \"v2.2.3\"}", false},
                //Does not match on exact group
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"group\": \"diff-group\", \"name\": \"acme-lib\", \"version\": \"v1.2.3\"}", "{\"group\": \"acme-app\", \"name\": \"acme-lib\", \"version\": \"v1.2.3\"}", true},
                //Does not match on version range greater than or equal
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"group\": \"acme-app\", \"name\": \"*acme-lib*\", \"version\": \">=v2.2.2\"}", "{\"group\": \"acme-app\", \"name\": \"acme-lib\", \"version\": \"v1.2.3\"}", true},
                //Matches without group
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"name\": \"Test Component\", \"version\": \"1.0.0\"}", "{\"name\": \"Test Component\", \"version\": \"1.0.0\"}", true},
                //Matches on wild card group
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"*\", \"name\": \"Test Component\", \"version\": \"1.0.0\"}", "{\"group\": \"Anything\", \"name\": \"Test Component\", \"version\": \"1.0.0\"}", true},
                //Matches on wild card name
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme-app\", \"name\": \"*\", \"version\": \"1.0.0\"}", "{\"group\": \"acme-app\", \"name\": \"Anything\", \"version\": \"1.0.0\"}", true},
                //Matches on wild card version
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"group\": \"acme-app\", \"name\": \"Test Component\", \"version\": \">=*\"}", "{\"group\": \"acme-app\", \"name\": \"Test Component\", \"version\": \"4.4.4\"}", true},
                //Matches on empty policy - uncomment after fixing script builder
                //new Object[]{PolicyCondition.Operator.MATCHES, "{}", "{}", true},
                //Does not match on lower version
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"== 1.1.1\"}", "{\"version\": \"0.1.1\"}", true},
                //Matches on equal version
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"== 1.1.1\"}", "{\"version\": \"1.1.1\"}", true},
                //Does not match on higher version
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"== 1.1.1\"}", "{\"version\": \"2.1.1\"}", true},
                //No match with version not equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"!= 1.1.1\"}", "{\"version\": \"1.1.1\"}", false},
                //Matches with version not equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"!= 1.1.1\"}", "{\"version\": \"2.1.1\"}", true},
                //Matches with version not equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"!= 1.1.1\"}", "{\"version\": \"0.1.1\"}", true},
                //Matches with version greater than
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"> 1.1.1\"}", "{\"version\": \"2.1.1\"}", true},
                //Does not match on version greater than
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"> 1.1.1\"}", "{\"version\": \"0.1.1\"}", false},
                //Does not match on version equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"> 1.1.1\"}", "{\"version\": \"1.1.1\"}", false},
                //No match with version greater than
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"> 1.1.1\"}", "{\"version\": \"0.1.1\"}", true},
                //No match with version equal to
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"> 1.1.1\"}", "{\"version\": \"1.1.1\"}", true},
                //No match with version greater than
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"> 1.1.1\"}", "{\"version\": \"2.1.1\"}", false},
                //Matches on version less than
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"<1.1.1\"}", "{\"version\": \"0.1.1\"}", true},
                //Does not match on version less than
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"<1.1.1\"}", "{\"version\": \"2.1.1\"}", false},
                //Does not match on equal version
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"<1.1.1\"}", "{\"version\": \"1.1.1\"}", false},
                //No match on version less than
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"<1.1.1\"}", "{\"version\": \"0.1.1\"}", false},
                //No match on version less than
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"<1.1.1\"}", "{\"version\": \"2.1.1\"}", true},
                //No match on equal version
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"<1.1.1\"}", "{\"version\": \"1.1.1\"}", true},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"<=1.1.1\"}", "{\"version\": \"0.1.1\"}", true},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"<=1.1.1\"}", "{\"version\": \"2.1.1\"}", false},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.MATCHES, "{\"version\": \"<=1.1.1\"}", "{\"version\": \"1.1.1\"}", true},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"<=1.1.1\"}", "{\"version\": \"0.1.1\"}", false},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"<=1.1.1\"}", "{\"version\": \"2.1.1\"}", true},
                //Matches on version less than equal to
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"version\": \"<=1.1.1\"}", "{\"version\": \"1.1.1\"}", false},
                //No match where component exactly matches condition
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"group\": \"Acme\", \"name\": \"Test Component\", \"version\": \"1.0.0\"}", "{\"group\": \"Acme\", \"name\": \"Test Component\", \"version\": \"1.0.0\"}", false},
                //No match where version differs
                new Object[]{PolicyCondition.Operator.NO_MATCH, "{\"group\": \"Acme\", \"name\": \"Test Component\", \"version\": \"1.0.0\"}", "{\"group\": \"Acme\", \"name\": \"Test Component\", \"version\": \"2.0.0\"}", true},
        };
    }

    @ParameterizedTest
    @MethodSource("parameters")
    public void testCondition(
            PolicyCondition.Operator operator,
            String conditionCoordinates,
            String componentCoordinates,
            boolean expectViolation) throws Exception {
        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, operator, conditionCoordinates);

        final JsonNode coordinatesNode = Mappers.jsonMapper().readTree(componentCoordinates);
        final String group = Optional.ofNullable(coordinatesNode.path("group").asText(null)).orElse("");
        final String name = Optional.ofNullable(coordinatesNode.path("name").asText(null)).orElse("");
        final String version = Optional.ofNullable(coordinatesNode.path("version").asText("")).orElse("");

        final var project = new Project();
        project.setName(group);
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setGroup(group);
        component.setName(name);
        component.setVersion(version);
        qm.persist(component);

        new CelPolicyEngine().evaluateProject(project.getUuid());
        if (expectViolation) {
            assertThat(qm.getAllPolicyViolations(component)).hasSize(1);
        } else {
            assertThat(qm.getAllPolicyViolations(component)).isEmpty();
        }
    }
}
