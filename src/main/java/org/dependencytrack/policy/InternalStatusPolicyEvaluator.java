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

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates whether a component's internal status violates a given policy.
 */
public class InternalStatusPolicyEvaluator extends AbstractPolicyEvaluator {

    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.IS_INTERNAL;
    }

    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();
        for (final PolicyCondition condition : super.extractSupportedConditions(policy)) {
            final boolean isInternal = Boolean.TRUE.equals(component.isInternal());
            switch (condition.getOperator()) {
                case IS:
                    if (!isInternal) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                    break;
                case IS_NOT:
                    if (isInternal) {
                        violations.add(new PolicyConditionViolation(condition, component));
                    }
                    break;
            }
        }
        return violations;
    }
}
