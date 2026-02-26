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
package org.dependencytrack.policy;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LatestVersionPolicyEvaluatorTest {

    private LatestVersionPolicyEvaluator evaluator;

    @BeforeEach
    void setup() {
        evaluator = new LatestVersionPolicyEvaluator();
    }

    private Policy policyWith(final PolicyCondition condition) {
        final Policy p = new Policy();
        p.setViolationState(Policy.ViolationState.FAIL);
        p.addPolicyCondition(condition);
        return p;
    }

    private RepositoryMetaComponent meta(final String latestVersion) {
        final RepositoryMetaComponent m = new RepositoryMetaComponent();
        m.setRepositoryType(RepositoryType.MAVEN);
        m.setName("demo");
        m.setNamespace("test");
        m.setLatestVersion(latestVersion);
        m.setPublished(new Date());
        m.setLastCheck(new Date());
        return m;
    }

    @Test
    void testUnknown_NoMetadata_ShouldViolate() {
        final Component c = new Component();
        c.setVersion("1.0.0");

        final PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.LATEST_VERSION_STATUS);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("UNKNOWN");

        final Policy policy = policyWith(condition);
        final List<PolicyConditionViolation> result = evaluator.evaluate(policy, c);

        assertEquals(1, result.size());
    }

    @Test
    void testUnknown_MetadataButMissingVersion_ShouldViolate() {
        final Component c = new Component();
        c.setVersion(null);
        c.setRepositoryMeta(meta("1.0.0"));

        final PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.LATEST_VERSION_STATUS);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("UNKNOWN");

        final Policy policy = policyWith(condition);
        final List<PolicyConditionViolation> result = evaluator.evaluate(policy, c);

        assertEquals(1, result.size());
    }

    @Test
    void testUnknown_WithMetadata_ShouldNotViolate() {
        final Component c = new Component();
        c.setVersion("1.0.0");
        c.setRepositoryMeta(meta("2.0.0")); 

        final PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.LATEST_VERSION_STATUS);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("UNKNOWN");

        final Policy policy = policyWith(condition);
        final List<PolicyConditionViolation> result = evaluator.evaluate(policy, c);

        assertTrue(result.isEmpty());
    }

    @Test
    void testLatest_WhenComponentIsLatest_ShouldViolate() {
        final Component c = new Component();
        c.setVersion("2.0.0");
        c.setRepositoryMeta(meta("2.0.0")); 

        final PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.LATEST_VERSION_STATUS);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("LATEST");

        final Policy policy = policyWith(condition);
        final List<PolicyConditionViolation> result = evaluator.evaluate(policy, c);

        assertEquals(1, result.size());
    }

    @Test
    void testLatest_WhenNotLatest_ShouldNotViolate() {
        final Component c = new Component();
        c.setVersion("1.5.0");
        c.setRepositoryMeta(meta("2.0.0")); 

        final PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.LATEST_VERSION_STATUS);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("LATEST");

        final Policy policy = policyWith(condition);
        final List<PolicyConditionViolation> result = evaluator.evaluate(policy, c);

        assertTrue(result.isEmpty());
    }

    @Test
    void testOutdated_WhenOlder_ShouldViolate() {
        final Component c = new Component();
        c.setVersion("1.5.0");
        c.setRepositoryMeta(meta("2.0.0")); 

        final PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.LATEST_VERSION_STATUS);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("OUTDATED");

        final Policy policy = policyWith(condition);
        final List<PolicyConditionViolation> result = evaluator.evaluate(policy, c);

        assertEquals(1, result.size());
    }

    @Test
    void testOutdated_WhenLatest_ShouldNotViolate() {
        final Component c = new Component();
        c.setVersion("2.0.0");
        c.setRepositoryMeta(meta("2.0.0")); 

        final PolicyCondition condition = new PolicyCondition();
        condition.setSubject(PolicyCondition.Subject.LATEST_VERSION_STATUS);
        condition.setOperator(PolicyCondition.Operator.IS);
        condition.setValue("OUTDATED");

        final Policy policy = policyWith(condition);
        final List<PolicyConditionViolation> result = evaluator.evaluate(policy, c);

        assertTrue(result.isEmpty());
    }
}

