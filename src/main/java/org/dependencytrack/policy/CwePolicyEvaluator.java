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

 import alpine.common.logging.Logger;
 import org.apache.commons.collections4.CollectionUtils;
 import org.dependencytrack.model.Component;
 import org.dependencytrack.model.Policy;
 import org.dependencytrack.model.PolicyCondition;
 import org.dependencytrack.model.Vulnerability;
 import org.dependencytrack.parser.common.resolver.CweResolver;

 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;

/**
 * Evaluates the Common Weakness Enumeration of component vulnerabilities against a policy.
 */
public class CwePolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(CwePolicyEvaluator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.CWE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();
        final List<PolicyCondition> policyConditions = super.extractSupportedConditions(policy);
        for (final Vulnerability vulnerability : qm.getAllVulnerabilities(component, false)) {
            for (final PolicyCondition condition: policyConditions) {
                LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition (" + condition.getUuid() + ")");
                if (matches(condition.getOperator(), vulnerability.getCwes(), condition.getValue())) {
                    violations.add(new PolicyConditionViolation(condition, component));
                }
            }
        }
        return violations;
    }

    public boolean matches(final PolicyCondition.Operator operator, final List<Integer> vulnerabilityCwes, final String conditionValue) {

        if (conditionValue == null || vulnerabilityCwes == null) {
            return false;
        }
        if("*".equals(conditionValue.trim())){
            return true;
        }
        List<Integer> cweIdsToMatch = new ArrayList<>();
        List<String> conditionCwes = Arrays.asList(conditionValue.split(","));
        conditionCwes.replaceAll(String::trim);
        conditionCwes.stream().forEach(cwe -> {
            Integer id = CweResolver.getInstance().parseCweString(cwe);
            if(id != null)
                cweIdsToMatch.add(id);
        });
        if (!cweIdsToMatch.isEmpty()) {
            if (PolicyCondition.Operator.CONTAINS_ANY == operator) {
                return CollectionUtils.containsAny(vulnerabilityCwes, cweIdsToMatch);
            } else if (PolicyCondition.Operator.CONTAINS_ALL == operator) {
                return CollectionUtils.containsAll(vulnerabilityCwes, cweIdsToMatch);
            }
        }
        return false;
    }

}