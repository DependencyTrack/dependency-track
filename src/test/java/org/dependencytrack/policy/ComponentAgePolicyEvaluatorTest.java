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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(Parameterized.class)
public class ComponentAgePolicyEvaluatorTest extends PersistenceCapableTest {

    @Parameterized.Parameters(name = "[{index}] publishedDate={0} operator={1} ageValue={2} shouldViolate={3}")
    public static Collection<?> testParameters() {
        return Arrays.asList(new Object[][]{
                // Component is older by one day.
                {Instant.now().minus(Duration.ofDays(667)), Operator.NUMERIC_GREATER_THAN, "P666D", true},
                {Instant.now().minus(Duration.ofDays(667)), Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "P666D", true},
                {Instant.now().minus(Duration.ofDays(667)), Operator.NUMERIC_EQUAL, "P666D", false},
                {Instant.now().minus(Duration.ofDays(667)), Operator.NUMERIC_NOT_EQUAL, "P666D", true},
                {Instant.now().minus(Duration.ofDays(667)), Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "P666D", false},
                {Instant.now().minus(Duration.ofDays(667)), Operator.NUMERIC_LESS_THAN, "P666D", false},
                // Component is newer by one day.
                {Instant.now().minus(Duration.ofDays(665)), Operator.NUMERIC_GREATER_THAN, "P666D", false},
                {Instant.now().minus(Duration.ofDays(665)), Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "P666D", false},
                {Instant.now().minus(Duration.ofDays(665)), Operator.NUMERIC_EQUAL, "P666D", false},
                {Instant.now().minus(Duration.ofDays(665)), Operator.NUMERIC_NOT_EQUAL, "P666D", true},
                {Instant.now().minus(Duration.ofDays(665)), Operator.NUMERIC_LESS_THAN, "P666D", true},
                // Component is exactly as old.
                {Instant.now().minus(Duration.ofDays(666)), Operator.NUMERIC_GREATER_THAN, "P666D", false},
                {Instant.now().minus(Duration.ofDays(666)), Operator.NUMERIC_GREATER_THAN_OR_EQUAL, "P666D", true},
                {Instant.now().minus(Duration.ofDays(666)), Operator.NUMERIC_EQUAL, "P666D", true},
                {Instant.now().minus(Duration.ofDays(666)), Operator.NUMERIC_NOT_EQUAL, "P666D", false},
                {Instant.now().minus(Duration.ofDays(666)), Operator.NUMERIC_LESSER_THAN_OR_EQUAL, "P666D", true},
                {Instant.now().minus(Duration.ofDays(666)), Operator.NUMERIC_LESS_THAN, "P666D", false},
                // Unsupported operator.
                {Instant.now().minus(Duration.ofDays(666)), Operator.MATCHES, "P666D", false},
                // Negative age period.
                {Instant.now().minus(Duration.ofDays(666)), Operator.NUMERIC_EQUAL, "P-666D", false},
                // Invalid age period format.
                {Instant.now().minus(Duration.ofDays(666)), Operator.NUMERIC_EQUAL, "foobar", false},
                // No known publish date.
                {null, Operator.NUMERIC_EQUAL, "P666D", false},
        });
    }

    private final Instant publishedDate;
    private final Operator operator;
    private final String ageValue;
    private final boolean shouldViolate;

    public ComponentAgePolicyEvaluatorTest(final Instant publishedDate, final Operator operator,
                                           final String ageValue, final boolean shouldViolate) {
        this.publishedDate = publishedDate;
        this.operator = operator;
        this.ageValue = ageValue;
        this.shouldViolate = shouldViolate;
    }

    @Test
    public void evaluateTest() {
        final var policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        final var condition = qm.createPolicyCondition(policy, Subject.AGE, operator, ageValue);

        final var metaComponent = new RepositoryMetaComponent();
        metaComponent.setRepositoryType(RepositoryType.MAVEN);
        metaComponent.setNamespace("foo");
        metaComponent.setName("bar");
        metaComponent.setLatestVersion("6.6.6");
        if (publishedDate != null) {
            metaComponent.setPublished(Date.from(publishedDate));
        }
        metaComponent.setLastCheck(new Date());
        qm.persist(metaComponent);

        final var component = new Component();
        component.setPurl("pkg:maven/foo/bar@1.2.3");

        final var evaluator = new ComponentAgePolicyEvaluator();
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