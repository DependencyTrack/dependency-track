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
import org.cyclonedx.model.Hash;

import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Component;

import org.dependencytrack.model.PolicyCondition;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates a components HASH against a policy.
 */
public class ComponentHashPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(ComponentHashPolicyEvaluator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.COMPONENT_HASH;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final List<PolicyConditionViolation> violations = new ArrayList<>();
        for (final PolicyCondition condition : super.extractSupportedConditions(policy)) {
            LOGGER.debug("Evaluating component (" + component.getUuid() + ") against policy condition (" + condition.getUuid() + ")");
            final Hash hash = extractHashValues(condition);
            if (conditionApplies(hash, component, condition.getOperator())) {
                LOGGER.info("Adding violation for component: " + component.getName() + " with condition: " + condition.getOperator());
                violations.add(new PolicyConditionViolation(condition, component));
            } else {
                LOGGER.info("No violation added for component: " + component.getName() + " with condition: " + condition.getOperator());
            }
        }
        return violations;
    }

    private Hash extractHashValues(PolicyCondition condition) {
        if (condition.getValue() == null) {
            return null;
        }
        final JSONObject def = new JSONObject(condition.getValue());
        return new Hash(
                def.optString("algorithm", null),
                def.optString("value", null)
        );
    }

    private boolean conditionApplies(Hash hash, Component component, PolicyCondition.Operator operator) {
        boolean matchFound = matches(hash, component);
        LOGGER.debug("Evaluating condition: " + operator + ", Match found: " + matchFound);

        return switch (operator) {
            case IS -> {
                LOGGER.info("IS Result: " + !matchFound);
                yield matchFound; // No Violation if the hash does not match
            }
            case IS_NOT -> {
                LOGGER.info("IS_NOT Result: " + matchFound);
                yield !matchFound; // Violation if the hash match
            }
            default -> {
                LOGGER.error("Unsupported operator: " + operator);
                yield false;
            }
        };
    }

    private boolean matches(Hash hash, Component component) {
        if (hash != null && hash.getAlgorithm() != null && hash.getValue() != null) {
            String value = StringUtils.trimToNull(hash.getValue());
            LOGGER.debug("Matching Hash: " + value + " with Component Hash for Algorithm: " + hash.getAlgorithm());
            if (Hash.Algorithm.MD5.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getMd5());
            } else if (Hash.Algorithm.SHA1.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getSha1());
            } else if (Hash.Algorithm.SHA_256.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getSha256());
            } else if (Hash.Algorithm.SHA_384.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getSha384());
            } else if (Hash.Algorithm.SHA_512.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getSha512());
            } else if (Hash.Algorithm.SHA3_256.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getSha3_256());
            } else if (Hash.Algorithm.SHA3_384.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getSha3_384());
            } else if (Hash.Algorithm.SHA3_512.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getSha3_512());
            } else if (Hash.Algorithm.BLAKE3.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getBlake3());
            } else if (Hash.Algorithm.BLAKE2b_256.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getBlake2b_256());
            } else if (Hash.Algorithm.BLAKE2b_384.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getBlake2b_384());
            } else if (Hash.Algorithm.BLAKE2b_512.getSpec().equalsIgnoreCase(hash.getAlgorithm())) {
                return value.equalsIgnoreCase(component.getBlake2b_512());
            }
        }
        LOGGER.info("No match found - hash or algorithm is null.");
        return false;
    }
}
