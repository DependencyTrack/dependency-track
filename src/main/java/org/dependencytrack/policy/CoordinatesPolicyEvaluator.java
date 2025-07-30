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
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Coordinates;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.util.ComponentVersion;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Evaluates a components group + name + version against a policy.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class CoordinatesPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(CoordinatesPolicyEvaluator.class);
    private static final Pattern VERSION_OPERATOR_PATTERN = Pattern.compile("^(?<operator>[<>]=?|[!=]=)\\s*");

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.COORDINATES;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();
        for (final PolicyCondition condition : super.extractSupportedConditions(policy)) {
            LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition (" + condition.getUuid() + ")");
            final Coordinates coordinates = parseCoordinatesDefinition(condition);
            final boolean positiveMatch = matches(coordinates.getGroup(), component.getGroup())
                    && matches(coordinates.getName(), component.getName())
                    && versionMatches(coordinates.getVersion(), component.getVersion());
            switch (condition.getOperator()) {
                case MATCHES -> {
                    if (positiveMatch) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                }
                case NO_MATCH -> {
                    if (!positiveMatch) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                }
                default -> {
                    // silently swallow this
                }
            }
        }
        return violations;
    }

    private boolean matches(final String conditionValue, final String part) {
        if (part == null) {
            return conditionValue == null;
        }

        final String p = StringUtils.trimToNull(part);
        return p == null || org.dependencytrack.policy.Matcher.matches(p, conditionValue);
    }

    private boolean versionMatches(final String conditionValue, final String part) {
        if (conditionValue == null && part == null) {
            return true;
        } else if (conditionValue == null ^ part == null) {
            return false;
        }
        final Matcher versionOperatorMatcher = VERSION_OPERATOR_PATTERN.matcher(conditionValue);
        if (!versionOperatorMatcher.find()) {
            // No operator provided, use default matching algorithm
            return matches(conditionValue, part);
        }

        final PolicyCondition.Operator versionOperator;
        switch (versionOperatorMatcher.group(1)) {
            case "==":
                versionOperator = PolicyCondition.Operator.NUMERIC_EQUAL;
                break;
            case "!=":
                versionOperator = PolicyCondition.Operator.NUMERIC_NOT_EQUAL;
                break;
            case "<":
                versionOperator = PolicyCondition.Operator.NUMERIC_LESS_THAN;
                break;
            case "<=":
                versionOperator = PolicyCondition.Operator.NUMERIC_LESSER_THAN_OR_EQUAL;
                break;
            case ">":
                versionOperator = PolicyCondition.Operator.NUMERIC_GREATER_THAN;
                break;
            case ">=":
                versionOperator = PolicyCondition.Operator.NUMERIC_GREATER_THAN_OR_EQUAL;
                break;
            default:
                versionOperator = null;
                break;
        }
        if (versionOperator == null) {
            // Shouldn't ever happen because the regex won't match anything else
            LOGGER.error("Failed to infer version operator from " + versionOperatorMatcher.group(1));
            return false;
        }

        final var componentVersion = new ComponentVersion(part);
        final var conditionVersion = new ComponentVersion(VERSION_OPERATOR_PATTERN.split(conditionValue)[1]);

        return VersionPolicyEvaluator.matches(componentVersion, conditionVersion, versionOperator);
    }

    /**
     * Expects the format of condition.getValue() to be:
     * <pre>
     * {
     *     'group': 'acme',
     *     'name': 'test component',
     *     'version': '1.0.0'
     * }
     * </pre>
     *
     * @param condition teh condition to evaluate
     * @return the Coordinates
     */
    private Coordinates parseCoordinatesDefinition(final PolicyCondition condition) {
        if (condition.getValue() == null) {
            return new Coordinates(null, null, null);
        }
        final JSONObject def = new JSONObject(condition.getValue());
        return new Coordinates(
                def.optString("group", null),
                def.optString("name", null),
                def.optString("version", null)
        );
    }

}
