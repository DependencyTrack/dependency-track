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
package org.dependencytrack.policy.cel.compat;

import org.dependencytrack.model.PolicyCondition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @since 5.0.0
 */
public class EpssCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(EpssCelPolicyScriptSourceBuilder.class);

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final double conditionValue;
        try {
            conditionValue = Double.parseDouble(policyCondition.getValue());
        } catch (RuntimeException e) {
            LOGGER.warn("Invalid value for EPSS condition: %s".formatted(policyCondition.getValue()), e);
            return null;
        }

        final String scriptSrcTemplate = switch (policyCondition.getOperator()) {
            case NUMERIC_GREATER_THAN -> "vulns.exists(vuln, vuln.epss_score > %s)";
            case NUMERIC_GREATER_THAN_OR_EQUAL -> "vulns.exists(vuln, vuln.epss_score >= %s)";
            case NUMERIC_EQUAL -> "vulns.exists(vuln, vuln.epss_score == %s)";
            case NUMERIC_NOT_EQUAL -> "vulns.exists(vuln, vuln.epss_score != %s)";
            case NUMERIC_LESSER_THAN_OR_EQUAL -> "vulns.exists(vuln, vuln.epss_score <= %s)";
            case NUMERIC_LESS_THAN -> "vulns.exists(vuln, vuln.epss_score < %s)";
            default -> null;
        };
        if (scriptSrcTemplate == null) {
            LOGGER.warn("Operator %s is not supported for EPSS conditions".formatted(policyCondition.getOperator()));
            return null;
        }

        return scriptSrcTemplate.formatted(conditionValue);
    }

}
