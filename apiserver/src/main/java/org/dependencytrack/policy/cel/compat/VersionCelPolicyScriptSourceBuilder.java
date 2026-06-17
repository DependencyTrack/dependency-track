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

import io.github.nscuro.versatile.Comparator;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import org.dependencytrack.model.PolicyCondition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.github.nscuro.versatile.version.KnownVersioningSchemes.SCHEME_GENERIC;

public class VersionCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {
    private static final Logger LOGGER = LoggerFactory.getLogger(VersionCelPolicyScriptSourceBuilder.class);

    @Override
    public String apply(PolicyCondition policyCondition) {

        Vers conditionVers = evaluateVers(policyCondition);
        if (conditionVers == null) {
            return null;
        }
        return """
                component.matches_range("%s")
                """.formatted(conditionVers.toString());
    }

    private static Vers evaluateVers(final PolicyCondition policyCondition) {
        try {
            switch (policyCondition.getOperator()) {
                case NUMERIC_EQUAL:
                    return Vers.builder(SCHEME_GENERIC)
                            .withConstraint(Comparator.EQUAL, policyCondition.getValue())
                            .build();
                case NUMERIC_NOT_EQUAL:
                    return Vers.builder(SCHEME_GENERIC)
                            .withConstraint(Comparator.NOT_EQUAL, policyCondition.getValue())
                            .build();
                case NUMERIC_LESS_THAN:
                    return Vers.builder(SCHEME_GENERIC)
                            .withConstraint(Comparator.LESS_THAN, policyCondition.getValue())
                            .build();
                case NUMERIC_LESSER_THAN_OR_EQUAL:
                    return Vers.builder(SCHEME_GENERIC)
                            .withConstraint(Comparator.LESS_THAN_OR_EQUAL, policyCondition.getValue())
                            .build();
                case NUMERIC_GREATER_THAN:
                    return Vers.builder(SCHEME_GENERIC)
                            .withConstraint(Comparator.GREATER_THAN, policyCondition.getValue())
                            .build();
                case NUMERIC_GREATER_THAN_OR_EQUAL:
                    return Vers.builder(SCHEME_GENERIC)
                            .withConstraint(Comparator.GREATER_THAN_OR_EQUAL, policyCondition.getValue())
                            .build();
                default:
                    LOGGER.warn("Unsupported operation {}", policyCondition.getOperator());
                    return null;
            }
        } catch (VersException versException) {
            LOGGER.warn("Unable to parse version range in policy condition", versException);
            return null;
        }
    }
}
