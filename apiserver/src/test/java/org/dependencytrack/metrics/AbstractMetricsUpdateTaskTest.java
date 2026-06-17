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
package org.dependencytrack.metrics;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;

import java.util.Date;
import java.util.UUID;

import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_CRITICAL;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_HIGH;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_LOW;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_MEDIUM;
import static org.dependencytrack.model.ConfigPropertyConstants.CUSTOM_RISK_SCORE_UNASSIGNED;

abstract class AbstractMetricsUpdateTaskTest extends PersistenceCapableTest {

    protected PolicyViolation createPolicyViolation(final Component component, final Policy.ViolationState violationState, final PolicyViolation.Type type) {
        final var policy = qm.createPolicy(UUID.randomUUID().toString(), Policy.Operator.ALL, violationState);
        final var policyCondition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "");
        final var policyViolation = new PolicyViolation();

        policyViolation.setComponent(component);
        policyViolation.setPolicyCondition(policyCondition);
        policyViolation.setTimestamp(new Date());
        policyViolation.setType(type);
        return qm.persist(policyViolation);
    }

    public void createTestConfigProperties(){
        qm.createConfigProperty(
            CUSTOM_RISK_SCORE_CRITICAL.getGroupName(), 
            CUSTOM_RISK_SCORE_CRITICAL.getPropertyName(), 
            CUSTOM_RISK_SCORE_CRITICAL.getDefaultPropertyValue(), 
            CUSTOM_RISK_SCORE_CRITICAL.getPropertyType(), 
            CUSTOM_RISK_SCORE_CRITICAL.getDescription()
        );
        qm.createConfigProperty(
            CUSTOM_RISK_SCORE_HIGH.getGroupName(), 
            CUSTOM_RISK_SCORE_HIGH.getPropertyName(), 
            CUSTOM_RISK_SCORE_HIGH.getDefaultPropertyValue(), 
            CUSTOM_RISK_SCORE_HIGH.getPropertyType(), 
            CUSTOM_RISK_SCORE_HIGH.getDescription()
        );
        qm.createConfigProperty(
            CUSTOM_RISK_SCORE_MEDIUM.getGroupName(), 
            CUSTOM_RISK_SCORE_MEDIUM.getPropertyName(), 
            CUSTOM_RISK_SCORE_MEDIUM.getDefaultPropertyValue(), 
            CUSTOM_RISK_SCORE_MEDIUM.getPropertyType(), 
            CUSTOM_RISK_SCORE_MEDIUM.getDescription()
        );
        qm.createConfigProperty(
            CUSTOM_RISK_SCORE_LOW.getGroupName(), 
            CUSTOM_RISK_SCORE_LOW.getPropertyName(), 
            CUSTOM_RISK_SCORE_LOW.getDefaultPropertyValue(), 
            CUSTOM_RISK_SCORE_LOW.getPropertyType(), 
            CUSTOM_RISK_SCORE_LOW.getDescription()
        );
        qm.createConfigProperty(
            CUSTOM_RISK_SCORE_UNASSIGNED.getGroupName(), 
            CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyName(), 
            CUSTOM_RISK_SCORE_UNASSIGNED.getDefaultPropertyValue(), 
            CUSTOM_RISK_SCORE_UNASSIGNED.getPropertyType(), 
            CUSTOM_RISK_SCORE_UNASSIGNED.getDescription()
        );
    }

}
