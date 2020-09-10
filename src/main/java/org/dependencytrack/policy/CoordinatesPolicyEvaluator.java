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

import alpine.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Coordinates;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.json.JSONObject;
import java.util.Optional;

/**
 * Evaluates a components group + name + version against a policy.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class CoordinatesPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(CoordinatesPolicyEvaluator.class);

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
    public Optional<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        for (final PolicyCondition condition: super.extractSupportedConditions(policy)) {
            LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition (" + condition.getUuid() + ")");
            final Coordinates coordinates = parseCoordinatesDefinition(condition);

            if (matches(condition.getOperator(), coordinates.getGroup(), component.getGroup())
                    && matches(condition.getOperator(), coordinates.getName(), component.getName())
                    && matches(condition.getOperator(), coordinates.getVersion(), component.getVersion())) {
                return Optional.of(new PolicyConditionViolation(condition, component));
            }
        }
        return Optional.empty();
    }

    private boolean matches(final PolicyCondition.Operator operator, final String conditionValue, final String part) {
        if (conditionValue == null && part == null) {
            return true;
        }
        final String p = StringUtils.trimToNull(part);
        if (PolicyCondition.Operator.MATCHES == operator) {
            if (p != null) {
                if ("*".equals(conditionValue)) {
                    return true;
                } else if (conditionValue != null && p.contains(conditionValue)) {
                    return true;
                }
            }
        } else if (PolicyCondition.Operator.NO_MATCH == operator) {
            if (p != null) {
                if ("*".equals(conditionValue)) {
                    return false;
                } else if (conditionValue != null && p.contains(conditionValue)) {
                    return false;
                }
                return true;
            }
        }
        return false;
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
