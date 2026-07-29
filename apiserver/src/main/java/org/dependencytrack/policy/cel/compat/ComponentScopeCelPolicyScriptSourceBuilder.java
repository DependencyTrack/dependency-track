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
import org.dependencytrack.model.Scope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public class ComponentScopeCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(ComponentScopeCelPolicyScriptSourceBuilder.class);

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final Scope scope;

        try {
            scope = extractScope(policyCondition);
        } catch (IllegalArgumentException exception) {
            LOGGER.warn("Policy value %s is not supported for this subject".formatted(policyCondition.getValue()));
            return null;
        }

        return switch (policyCondition.getOperator()) {
            case IS -> formatIsOperator(scope);
            case IS_NOT -> formatIsNotOperator(scope);
            default -> {
                LOGGER.warn("Policy operator %s is not supported for this subject".formatted(policyCondition.getOperator()));
                yield null;
            }
        };
    }

    private static Scope extractScope(PolicyCondition condition) {
        final String value = condition.getValue().toUpperCase();

        if (value.equals("UNASSIGNED")) {
            return null;
        }

        return Scope.valueOf(value);
    }

    private static String formatIsOperator(Scope scope) {
        return scope == null
                ? "!has(component.scope)"
                : """
                    component.scope == "%s"
                    """.formatted(escapeQuotes(scope.toString()));
    }

    private static String formatIsNotOperator(Scope scope) {
        return scope == null
                ? "has(component.scope)"
                : """
                    component.scope != "%s"
                    """.formatted(escapeQuotes(scope.toString()));
    }
}
