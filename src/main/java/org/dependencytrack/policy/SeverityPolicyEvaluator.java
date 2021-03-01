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
import org.dependencytrack.model.Vulnerability;
import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates the severity of component vulnerabilities against a policy.
 *
 * @author Steve Springett
 * @since 4.1.0
 */
public class SeverityPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(SeverityPolicyEvaluator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.SEVERITY;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();
        final List<PolicyCondition> policyConditions = super.extractSupportedConditions(policy);
        //final Component component = qm.getObjectById(Component.class, c.getId());
        for (final Vulnerability vulnerability : qm.getAllVulnerabilities(component, false)) {
            for (final PolicyCondition condition: policyConditions) {
                LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition (" + condition.getUuid() + ")");
                if (PolicyCondition.Operator.IS == condition.getOperator()) {
                    if (vulnerability.getSeverity().name().equals(condition.getValue())) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                } else if (PolicyCondition.Operator.IS_NOT == condition.getOperator()) {
                    if (! vulnerability.getSeverity().name().equals(condition.getValue())) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                }
            }
        }
        return violations;
    }

}
