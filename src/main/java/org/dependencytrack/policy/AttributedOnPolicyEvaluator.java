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

import org.dependencytrack.model.Component;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Evaluates vulnerabilities against attributed on age-based policy conditions.
 * <p>
 * Checks whether vulnerabilities meet age requirements by comparing their
 * attribution date with specified time periods in ISO-8601 format (e.g., "P30D").
 */
public class AttributedOnPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = LoggerFactory.getLogger(AttributedOnPolicyEvaluator.class);
    private static final ConcurrentMap<String, Optional<Period>> PERIOD_CACHE = new ConcurrentHashMap<>();
    private static final int MAX_CACHE_SIZE = 100;

    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.ATTRIBUTED_ON;
    }

    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        if (policy == null || component == null) {
            return Collections.emptyList();
        }

        final List<PolicyCondition> conditions = extractSupportedConditions(policy);
        if (conditions.isEmpty()) {
            return Collections.emptyList();
        }

        final List<Vulnerability> vulnerabilities = getVulnerabilities(component);
        if (vulnerabilities.isEmpty()) {
            return Collections.emptyList();
        }

        return evaluateVulnerabilities(vulnerabilities, conditions, component);
    }

    /**
     * Retrieves all vulnerabilities for the given component.
     *
     * @param component the component to get vulnerabilities for
     * @return list of vulnerabilities, never null
     */
    private List<Vulnerability> getVulnerabilities(final Component component) {
        try {
            final List<Vulnerability> vulnerabilities = qm.getAllVulnerabilities(component);
            return vulnerabilities != null ? vulnerabilities : Collections.emptyList();
        } catch (final Exception e) {
            LOGGER.warn("Failed to retrieve vulnerabilities for component: {}", component.getUuid(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Evaluates vulnerabilities against policy conditions.
     *
     * @param vulnerabilities  the vulnerabilities to evaluate
     * @param conditions the policy conditions to check against
     * @param component        the component being evaluated
     * @return list of policy violations
     */
    private List<PolicyConditionViolation> evaluateVulnerabilities(
            final List<Vulnerability> vulnerabilities,
            final List<PolicyCondition> conditions,
            final Component component) {

        final List<PolicyConditionViolation> violations = new ArrayList<>();

        for (final Vulnerability vulnerability : vulnerabilities) {
            final Optional<Date> attributedDate = getAttributedOnDate(vulnerability, component);
            if (attributedDate.isEmpty()) {
                continue;
            }

            for (final PolicyCondition condition : conditions) {
                if (evaluateCondition(condition, attributedDate.get())) {
                    violations.add(new PolicyConditionViolation(condition, component));
                }
            }
        }

        return violations;
    }

    /**
     * Extracts the attributed on date from a vulnerability.
     *
     * @param vulnerability the vulnerability to extract the date from
     * @param component     the component associated with the vulnerability
     * @return the attributed on date wrapped in Optional, empty if not available
     */
    private Optional<Date> getAttributedOnDate(final Vulnerability vulnerability, final Component component) {
        try {
            final FindingAttribution attribution = qm.getFindingAttribution(vulnerability, component);
            return attribution != null ? Optional.ofNullable(attribution.getAttributedOn()) : Optional.empty();
        } catch (final Exception e) {
            LOGGER.debug("Failed to retrieve attribution for vulnerability {} on component {}",
                    vulnerability.getVulnId(), component.getUuid());
            return Optional.empty();
        }
    }

    /**
     * Evaluates a single policy condition against an attributed on date.
     *
     * @param condition    the policy condition to evaluate
     * @param attributedOn the date when the vulnerability was attributed
     * @return true if the condition is violated, false otherwise
     * @throws IllegalArgumentException if condition or attributedOn is null
     */
    private boolean evaluateCondition(final PolicyCondition condition, final Date attributedOn) {
        final Optional<Period> agePeriod = parseAgePeriod(condition.getValue());
        if (agePeriod.isEmpty() || !isValidPeriod(agePeriod.get())) {
            return false;
        }

        final LocalDate attributedDate = attributedOn.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
        final LocalDate targetDate = attributedDate.plus(agePeriod.get());
        final LocalDate today = LocalDate.now();

        return switch (condition.getOperator()) {
            case NUMERIC_GREATER_THAN -> targetDate.isBefore(today);
            case NUMERIC_GREATER_THAN_OR_EQUAL -> !targetDate.isAfter(today);
            case NUMERIC_EQUAL -> targetDate.isEqual(today);
            case NUMERIC_NOT_EQUAL -> !targetDate.isEqual(today);
            case NUMERIC_LESSER_THAN_OR_EQUAL -> !targetDate.isBefore(today);
            case NUMERIC_LESS_THAN -> targetDate.isAfter(today);
            default -> false;
        };
    }

    private Optional<Period> parseAgePeriod(final String periodValue) {
        if (periodValue == null || periodValue.trim().isEmpty()) {
            return Optional.empty();
        }

        final String trimmed = periodValue.trim();
        Optional<Period> cached = PERIOD_CACHE.get(trimmed);
        if (cached != null) {
            return cached;
        }

        try {
            final Period period = Period.parse(trimmed);
            cached = Optional.of(period);
        } catch (final DateTimeParseException e) {
            cached = Optional.empty();
        }

        if (PERIOD_CACHE.size() < MAX_CACHE_SIZE) {
            PERIOD_CACHE.put(trimmed, cached);
        }

        return cached;
    }

    private boolean isValidPeriod(final Period period) {
        return !period.isZero() && !period.isNegative();
    }
}