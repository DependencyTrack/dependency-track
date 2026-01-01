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

import alpine.common.logging.Logger;
import io.github.nscuro.versatile.VersionFactory;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.spi.Version;

import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.util.ComponentVersion;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates a components version against a policy.
 *
 * @since 4.2.0
 */
public class VersionPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(VersionPolicyEvaluator.class);

    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.VERSION;
    }

    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();

        final List<PolicyCondition> policyConditions = super.extractSupportedConditions(policy);
        if (policyConditions.isEmpty()) {
            return violations;
        }

        final var componentVersion = component.getVersion();
        final var componentPurl = component.getPurl();
        final var scheme = componentPurl != null && componentPurl.getType() != null ? componentPurl.getType()
                : "generic";
        final Version componentVersionObj;

        try {
            componentVersionObj = VersionFactory.forScheme(scheme, componentVersion);
        } catch (InvalidVersionException e) {
            LOGGER.warn(
                    "Unable to parse version (" + componentVersion + ") for component (" + component.getUuid() + ")");
            return violations;
        }

        for (final PolicyCondition condition : super.extractSupportedConditions(policy)) {
            LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition ("
                    + condition.getUuid() + ")");

            final var conditionVersionObj = VersionFactory.forScheme(scheme, condition.getValue());
            if (conditionVersionObj == null) {
                LOGGER.warn("Unable to parse version (" + condition.getValue() + " provided by condition");
                continue;
            }
            if (matches(componentVersionObj, conditionVersionObj, condition.getOperator())) {
                violations.add(new PolicyConditionViolation(condition, component));
            }

        }

        return violations;
    }

    static boolean matches(final Version componentVersionObj,
            final Version conditionVersionObj,
            final PolicyCondition.Operator operator) {
        final int comparisonResult = componentVersionObj.compareTo(conditionVersionObj);
        switch (operator) {
            case NUMERIC_EQUAL:
                return comparisonResult == 0;
            case NUMERIC_NOT_EQUAL:
                return comparisonResult != 0;
            case NUMERIC_LESS_THAN:
                return comparisonResult < 0;
            case NUMERIC_LESSER_THAN_OR_EQUAL:
                return comparisonResult <= 0;
            case NUMERIC_GREATER_THAN:
                return comparisonResult > 0;
            case NUMERIC_GREATER_THAN_OR_EQUAL:
                return comparisonResult >= 0;
            default:
                LOGGER.warn("Unsupported operation " + operator);
                break;
        }
        return false;
    }


    static boolean matches(final ComponentVersion componentVersion,
                           final ComponentVersion conditionVersion,
                           final PolicyCondition.Operator operator) {
        final int comparisonResult = componentVersion.compareTo(conditionVersion);
        switch (operator) {
            case NUMERIC_EQUAL:
                return comparisonResult == 0;
            case NUMERIC_NOT_EQUAL:
                return comparisonResult != 0;
            case NUMERIC_LESS_THAN:
                return comparisonResult < 0;
            case NUMERIC_LESSER_THAN_OR_EQUAL:
                return comparisonResult <= 0;
            case NUMERIC_GREATER_THAN:
                return comparisonResult > 0;
            case NUMERIC_GREATER_THAN_OR_EQUAL:
                return comparisonResult >= 0;
            default:
                LOGGER.warn("Unsupported operation " + operator);
                break;
        }
        return false;
    }
}