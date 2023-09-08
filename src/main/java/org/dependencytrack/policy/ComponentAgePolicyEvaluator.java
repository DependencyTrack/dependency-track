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
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.RepositoryMetaComponent;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.persistence.QueryManager;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Evaluates a {@link Component}'s published date against a {@link Policy}.
 * <p>
 * Age values can be provided in ISO-8601 period format, see {@link Period#parse(CharSequence)}.
 *
 * @since 4.8.0
 */
public class ComponentAgePolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = Logger.getLogger(ComponentAgePolicyEvaluator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.AGE;
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
        if (metaComponent == null || metaComponent.getPublished() == null) {
            return violations;
        }

        for (final PolicyCondition condition : super.extractSupportedConditions(policy)) {
            if (evaluate(condition, metaComponent.getPublished())) {
                violations.add(new PolicyConditionViolation(condition, component));
            }
        }

        return violations;
    }

    private boolean evaluate(final PolicyCondition condition, final Date published) {
        final Period agePeriod;
        try {
            agePeriod = Period.parse(condition.getValue());
        } catch (DateTimeParseException e) {
            LOGGER.error("Invalid age duration format", e);
            return false;
        }

        if (agePeriod.isZero() || agePeriod.isNegative()) {
            LOGGER.warn("Age durations must not be zero or negative");
            return false;
        }

        final LocalDate publishedDate = LocalDate.ofInstant(published.toInstant(), ZoneId.systemDefault());
        final LocalDate ageDate = publishedDate.plus(agePeriod);
        final LocalDate today = LocalDate.now();

        return switch (condition.getOperator()) {
            case NUMERIC_GREATER_THAN -> ageDate.isBefore(today);
            case NUMERIC_GREATER_THAN_OR_EQUAL -> ageDate.isEqual(today) || ageDate.isBefore(today);
            case NUMERIC_EQUAL -> ageDate.isEqual(today);
            case NUMERIC_NOT_EQUAL -> !ageDate.isEqual(today);
            case NUMERIC_LESSER_THAN_OR_EQUAL -> ageDate.isEqual(today) || ageDate.isAfter(today);
            case NUMERIC_LESS_THAN -> ageDate.isAfter(today);
            default -> {
                LOGGER.warn("Operator %s is not supported for component age conditions".formatted(condition.getOperator()));
                yield false;
            }
        };
    }

}
