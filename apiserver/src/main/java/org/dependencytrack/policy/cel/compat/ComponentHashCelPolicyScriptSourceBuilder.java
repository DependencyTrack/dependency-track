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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.cyclonedx.model.Hash;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.model.PolicyCondition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UncheckedIOException;

import static org.dependencytrack.policy.cel.compat.CelPolicyScriptSourceBuilder.escapeQuotes;

public class ComponentHashCelPolicyScriptSourceBuilder implements CelPolicyScriptSourceBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(ComponentHashCelPolicyScriptSourceBuilder.class);

    @Override
    public String apply(final PolicyCondition policyCondition) {
        final Hash hash = extractHashValues(policyCondition);
        if (hash.getAlgorithm() == null || hash.getValue() == null || hash.getAlgorithm().isEmpty() || hash.getValue().isEmpty()) {
            return null;
        }

        final String fieldName = hash.getAlgorithm().toLowerCase().replaceAll("-", "_");
        if (org.dependencytrack.proto.policy.v1.Component.getDescriptor().findFieldByName(fieldName) == null) {
            LOGGER.warn("Component does not have a field named %s".formatted(fieldName));
            return null;
        }
        return switch (policyCondition.getOperator()) {
            case IS -> """
                    component.%s == "%s"
                    """.formatted(fieldName, escapeQuotes(hash.getValue()));
            case IS_NOT -> """
                    component.%s != "%s"
                    """.formatted(fieldName, escapeQuotes(hash.getValue()));
            default -> {
                LOGGER.warn("Policy operator %s is not supported for this subject".formatted(policyCondition.getOperator()));
                yield null;
            }
        };
    }

    private static Hash extractHashValues(PolicyCondition condition) {
        final JsonNode valueNode;
        try {
            valueNode = Mappers.jsonMapper().readTree(condition.getValue());
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }

        return new Hash(
                valueNode.path("algorithm").asText(null),
                valueNode.path("value").asText(null)
        );
    }

}
