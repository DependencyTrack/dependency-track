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

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Vulnerability;

import alpine.common.logging.Logger;

public class EpssPolicyEvaluator extends AbstractPolicyEvaluator {
    private static final Logger LOGGER = Logger.getLogger(EpssPolicyEvaluator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.EPSS;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();

        final List<PolicyCondition> policyConditions = super.extractSupportedConditions(policy);
        if (policyConditions.isEmpty()) {
            return violations;
        }

        for (final Vulnerability vulnerability : qm.getAllVulnerabilities(component, false)) {
            for (final PolicyCondition condition: policyConditions) {
                LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition (" + condition.getUuid() + ")");
                if (matches(condition.getOperator(), vulnerability.getEpssScore(), condition.getValue())) {
                    violations.add(new PolicyConditionViolation(condition, component));
                }
            }
            
        }
        return violations;
    }

    public boolean matches(final PolicyCondition.Operator operator, final BigDecimal vulnerabilityEpss, final String conditionValue) {

        if (conditionValue == null || vulnerabilityEpss == null) {
            return false;
        }
        BigDecimal conditionDecimalValue = new BigDecimal(conditionValue);
        
        return switch (operator) {
            case NUMERIC_GREATER_THAN -> vulnerabilityEpss.compareTo(conditionDecimalValue) > 0;
            case NUMERIC_GREATER_THAN_OR_EQUAL -> vulnerabilityEpss.compareTo(conditionDecimalValue) >= 0;
            case NUMERIC_EQUAL -> vulnerabilityEpss.compareTo(conditionDecimalValue) == 0;
            case NUMERIC_NOT_EQUAL -> vulnerabilityEpss.compareTo(conditionDecimalValue) != 0;
            case NUMERIC_LESSER_THAN_OR_EQUAL -> vulnerabilityEpss.compareTo(conditionDecimalValue) <= 0;
            case NUMERIC_LESS_THAN -> vulnerabilityEpss.compareTo(conditionDecimalValue) < 0;
            default -> {
                LOGGER.warn("Operator %s is not supported for EPSS conditions".formatted(operator));
                yield false;
            }
        };

    }
}
