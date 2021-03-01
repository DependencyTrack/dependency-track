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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates a components Package URL against a policy.
 *
 * @author Steve Springett
 * @since 4.0.0
 */
public class PackageURLPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(PackageURLPolicyEvaluator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.PACKAGE_URL;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();
        if (component.getPurl() == null) {
            return violations;
        }
        for (final PolicyCondition condition: super.extractSupportedConditions(policy)) {
            LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition (" + condition.getUuid() + ")");
            if (PolicyCondition.Operator.MATCHES == condition.getOperator()) {
                if (component.getPurl() != null) {
                    if (component.getPurl().canonicalize().contains(condition.getValue())) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                }
                if (component.getPurlCoordinates() != null) {
                    if (component.getPurlCoordinates().canonicalize().contains(condition.getValue())) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                }
            } else if (PolicyCondition.Operator.NO_MATCH == condition.getOperator()) {
                if (component.getPurl() != null && component.getPurlCoordinates() != null) {
                    if (!component.getPurl().canonicalize().contains(condition.getValue())
                            && !component.getPurlCoordinates().canonicalize().contains(condition.getValue()) ) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                } else if (component.getPurl() != null) {
                    if (!component.getPurl().canonicalize().contains(condition.getValue())) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                }
            }
        }
        return violations;
    }

}
