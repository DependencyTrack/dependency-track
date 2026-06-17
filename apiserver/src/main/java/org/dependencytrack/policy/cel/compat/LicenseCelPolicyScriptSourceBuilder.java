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
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public final class LicenseCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(LicenseCelPolicyScriptSourceBuilder.class);

    /// Expression to determine the effective component license expression
    /// to evaluate, matching v4's LicensePolicyEvaluator.
    ///
    /// Users should generally be steered to writing the CEL expressions
    /// themselves, and making the field selection explicit.
    static final String EFFECTIVE_COMPONENT_LICENSE_EXPR = """
            (component.resolved_license.id != ""
              ? component.resolved_license.id
              : (component.resolved_license.name != ""
                  ? component.resolved_license.name
                  : (component.license_expression != ""
                      ? component.license_expression
                      : (component.license_name != ""
                          ? component.license_name
                          : "unresolved"))))""";

    /// Expression to determine whether the component should be treated
    /// as having an unresolved license. Again, this matches v4's
    /// LicensePolicyEvaluator, which doesn't mean it's strictly correct.
    private static final String IS_COMPONENT_LICENSE_UNRESOLVED_EXPR = """
            !has(component.resolved_license) \
              && component.license_expression == "" \
              && component.license_name == ""\
            """;

    @Override
    public String apply(PolicyCondition policyCondition) {
        final String value = policyCondition.getValue();
        if (value == null) {
            return null;
        }

        if ("unresolved".equals(value)) {
            return switch (policyCondition.getOperator()) {
                case IS -> IS_COMPONENT_LICENSE_UNRESOLVED_EXPR;
                case IS_NOT -> "!(%s)".formatted(IS_COMPONENT_LICENSE_UNRESOLVED_EXPR);
                default -> null;
            };
        }

        // Unfortunately, the legacy v4 behavior of this condition is a bit overloaded.
        // It does not only check EQUALITY, but also applies SPDX expression logic.
        // The condition as configured by users only gives us a license UUID,
        // which ofc does not suffice for SPDX expression evaluation.
        //
        // We don't have another choice than do a DB lookup here to resolve the license ID.
        // DO NOT REPEAT THIS PATTERN ELSEWHERE. Script builders were intended to be thin
        // translation layers, and not do any I/O whatsoever.
        final ConditionLicense conditionLicense = tryLookupLicense(value);
        if (conditionLicense == null) {
            LOGGER.warn(
                    "No license with UUID {} exists; Skipping condition {}",
                    value, policyCondition.getUuid());
            return null;
        }

        final String escapedId = escapeQuotes(conditionLicense.licenseId());
        final String escapedName = escapeQuotes(conditionLicense.name());
        return switch (policyCondition.getOperator()) {
            case IS -> """
                    %1$s in ["%2$s", "%3$s"] || spdx_expr_requires_any(%1$s, ["%2$s"])\
                    """.formatted(EFFECTIVE_COMPONENT_LICENSE_EXPR, escapedId, escapedName);
            case IS_NOT -> """
                    !(%1$s in ["%2$s", "%3$s"]) && !spdx_expr_allows(%1$s, ["%2$s"])\
                    """.formatted(EFFECTIVE_COMPONENT_LICENSE_EXPR, escapedId, escapedName);
            default -> null;
        };
    }

    record ConditionLicense(@Nullable String licenseId, String name) {
    }

    private static @Nullable ConditionLicense tryLookupLicense(String licenseUuid) {
        try {
            return withJdbiHandle(
                    handle -> handle
                            .createQuery("""
                                    SELECT COALESCE("LICENSEID", '')
                                         , "NAME" -- NOT NULL
                                      FROM "LICENSE"
                                     WHERE "UUID" = CAST(:uuid AS UUID)
                                    """)
                            .bind("uuid", licenseUuid)
                            .map((rs, _) -> new ConditionLicense(
                                    rs.getString(1),
                                    rs.getString(2)))
                            .findOne()
                            .orElse(null));
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to look up license with UUID {}", licenseUuid, e);
            return null;
        }
    }

}
