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
import org.dependencytrack.policy.cel.compat.LicenseCelPolicyScriptSourceBuilder.ConditionLicense;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.policy.cel.compat.LicenseCelPolicyScriptSourceBuilder.EFFECTIVE_COMPONENT_LICENSE_EXPR;

public final class LicenseGroupCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(LicenseGroupCelPolicyScriptSourceBuilder.class);

    @Override
    public String apply(PolicyCondition policyCondition) {
        final String value = policyCondition.getValue();
        if (value == null) {
            return null;
        }

        final List<ConditionLicense> licensesInGroup = tryLookupLicensesOfGroup(value);
        if (licensesInGroup == null) {
            return null;
        }
        
        final String licenseIds = licensesInGroup.stream()
                .map(ConditionLicense::licenseId)
                .filter(Objects::nonNull)
                .map(CelPolicyScriptSourceBuilder::escapeQuotes)
                .map("\"%s\""::formatted)
                .collect(Collectors.joining(", ", "[", "]"));
        final String licenseNames = licensesInGroup.stream()
                .map(ConditionLicense::name)
                .filter(Objects::nonNull)
                .map(CelPolicyScriptSourceBuilder::escapeQuotes)
                .map("\"%s\""::formatted)
                .collect(Collectors.joining(", ", "[", "]"));

        return switch (policyCondition.getOperator()) {
            case IS -> """
                    %1$s.exists(id, id == %3$s) \
                    || %2$s.exists(name, name == %3$s) \
                    || spdx_expr_requires_any(%3$s, %1$s)\
                    """.formatted(licenseIds, licenseNames, EFFECTIVE_COMPONENT_LICENSE_EXPR);
            case IS_NOT -> """
                    !%1$s.exists(id, id == %3$s) \
                    && !%2$s.exists(name, name == %3$s) \
                    && !spdx_expr_allows(%3$s, %1$s)\
                    """.formatted(licenseIds, licenseNames, EFFECTIVE_COMPONENT_LICENSE_EXPR);
            default -> null;
        };
    }

    private static List<ConditionLicense> tryLookupLicensesOfGroup(String groupUuid) {
        try {
            return withJdbiHandle(
                    handle -> handle
                            .createQuery("""
                                    SELECT l."LICENSEID"
                                         , l."NAME"
                                      FROM "LICENSE" AS l
                                     INNER JOIN "LICENSEGROUP_LICENSE" AS lgl
                                        ON lgl."LICENSE_ID" = l."ID"
                                     INNER JOIN "LICENSEGROUP" AS lg
                                        ON lg."ID" = lgl."LICENSEGROUP_ID"
                                     WHERE lg."UUID" = CAST(:uuid AS UUID)
                                    """)
                            .bind("uuid", groupUuid)
                            .map((rs, _) -> new ConditionLicense(
                                    rs.getString(1),
                                    rs.getString(2)))
                            .list());
        } catch (RuntimeException e) {
            LOGGER.warn("Failed to look up license group with UUID {}", groupUuid, e);
            return null;
        }
    }

}
