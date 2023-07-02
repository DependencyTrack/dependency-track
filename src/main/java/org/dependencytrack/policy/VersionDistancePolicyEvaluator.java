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

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.VersionDistance;
import org.json.JSONObject;

import alpine.common.logging.Logger;

/**
 * Evaluates the {@link VersionDistance} between a {@link Component}'s current and it's latest
 * version against a {@link Policy}. This makes it possible to add a policy for checking outdated
 * components. The policy "greater than 0:1.?.?" for example means, a difference of only one
 * between the curren version's major number and the latest version's major number is allowed.
 *
 * VersionDistances can be combined in a policy. For example "greater than 1:1.?.?" means a
 * difference of only one epoch number or one major number is allowed. Or "greater than 1.1.?"
 * means a difference of only one majr number or one minor number is allowed
 *
 * @since 4.9.0
 */
public class VersionDistancePolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(VersionDistancePolicyEvaluator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.VERSION_DISTANCE;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        final var violations = new ArrayList<PolicyConditionViolation>();
        if (component.getPurl() == null) {
            return violations;
        }

        final RepositoryType repoType = RepositoryType.resolve(component.getPurl());
        if (RepositoryType.UNSUPPORTED == repoType) {
            return violations;
        }

        final RepositoryMetaComponent metaComponent;
        try (final var qm = new QueryManager()) {
            metaComponent = qm.getRepositoryMetaComponent(repoType,
                    component.getPurl().getNamespace(), component.getPurl().getName());
            qm.getPersistenceManager().detachCopy(metaComponent);
        }
        if (metaComponent == null || metaComponent.getLatestVersion() == null) {
            return violations;
        }

        final var versionDistance = VersionDistance.getVersionDistance(component.getVersion(),metaComponent.getLatestVersion());

        for (final PolicyCondition condition : super.extractSupportedConditions(policy)) {
            if (isDirectDependency(component) && evaluate(condition, versionDistance)) {
                violations.add(new PolicyConditionViolation(condition, component));
            }
        }

        return violations;
    }

    /**
     * Evaluate VersionDistance conditions for a given versionDistance. A condition
     *
     * @param condition operator and value containing combined {@link VersionDistance} values
     * @param versionDistance the {@link VersionDistance} to evalue
     * @return true if the condition is true for the components versionDistance, false otherwise
     */
    private boolean evaluate(final PolicyCondition condition, final VersionDistance versionDistance) {
        final var operator = condition.getOperator();
        final var value = condition.getValue();

        if (!StringUtils.isEmpty(value)) {
            final var json = new JSONObject(value);
            final var epoch = json.optString("epoch", "0");
            final var major = json.optString("major", "?");
            final var minor = json.optString("minor", "?");
            final var patch = json.optString("patch", "?");

            final List<VersionDistance> versionDistanceList;
            try {
                versionDistanceList = VersionDistance.parse(epoch+":"+major+"."+minor+"."+patch);
            } catch (IllegalArgumentException e) {
                LOGGER.error("Invalid version distance format", e);
                return false;
            }
            if (versionDistanceList.isEmpty()) {
                versionDistanceList.add(new VersionDistance(0,0,0));
            }
            return versionDistanceList.stream().reduce(
                false,
                (latest, current) -> latest || matches(operator, current, versionDistance),
                Boolean::logicalOr
            );
        }
        return false;



    }

    private boolean matches(final Operator operator, final VersionDistance policyDistance, final VersionDistance versionDistance) {
        return switch (operator) {
            case NUMERIC_GREATER_THAN -> versionDistance.compareTo(policyDistance) > 0;
            case NUMERIC_GREATER_THAN_OR_EQUAL -> versionDistance.compareTo(policyDistance) >= 0;
            case NUMERIC_EQUAL -> versionDistance.compareTo(policyDistance) == 0;
            case NUMERIC_NOT_EQUAL -> versionDistance.compareTo(policyDistance) != 0;
            case NUMERIC_LESSER_THAN_OR_EQUAL -> versionDistance.compareTo(policyDistance) <= 0;
            case NUMERIC_LESS_THAN -> versionDistance.compareTo(policyDistance) < 0;
            default -> {
                LOGGER.warn("Operator %s is not supported for component age conditions".formatted(operator));
                yield false;
            }
        };
    }

    /**
     * Test if the components project direct dependencies contain a givven component
     * If so, the component is a direct dependency of the project
     *
     * @param component component to test
     * @return If the components project direct dependencies contain the component
     */
    private boolean isDirectDependency(Component component) {
        return component.getProject().getDirectDependencies().contains("\"uuid\":\"" + component.getUuid().toString() + "\"");
    }

}