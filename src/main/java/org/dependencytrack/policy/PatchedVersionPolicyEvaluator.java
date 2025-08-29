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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Vulnerability;

import java.util.ArrayList;
import java.util.List;

public class PatchedVersionPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(PatchedVersionPolicyEvaluator.class);

    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.PATCH_VERSION;
    }

    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();
        final List<PolicyCondition> policyConditions = super.extractSupportedConditions(policy);

        if (policyConditions.isEmpty    ()) {
            return violations;
        }

        for (final Vulnerability vulnerability : qm.getAllVulnerabilities(component, false)) {
            final boolean hasPatchedVersion = vulnerability.getPatchedVersions() != null &&
                    !vulnerability.getPatchedVersions().trim().isEmpty();

            for (final PolicyCondition condition : policyConditions) {
                LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition (" + condition.getUuid() + ")");

                final String value = condition.getValue();
                if (!"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value)) {
                    LOGGER.warn("Invalid condition value for PATCHED_VERSION subject. Expected 'true' or 'false', found: " + value);
                    continue;
                }

                final boolean expected = Boolean.parseBoolean(value);

                if (PolicyCondition.Operator.IS == condition.getOperator() && hasPatchedVersion == expected) {
                    violations.add(new PolicyConditionViolation(condition, component));
                } else if (PolicyCondition.Operator.IS_NOT == condition.getOperator() && hasPatchedVersion != expected) {
                    violations.add(new PolicyConditionViolation(condition, component));
                }
            }
        }

        return violations;
    }
}