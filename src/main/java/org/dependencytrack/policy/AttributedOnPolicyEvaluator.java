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

import java.time.Clock;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Evaluates a {@link Vulnerability}'s attributed on date against a {@link Policy}.
 * <p>
 * This evaluator checks whether vulnerabilities meet age-based policy conditions
 * by comparing their attribution date with specified time periods.
 * <p>
 * Age values must be provided in ISO-8601 period format (e.g., "P30D" for 30 days,
 * "P1M" for 1 month). See {@link Period#parse(CharSequence)} for format details.
 *
 * <p>
 * This class is thread-safe and uses caching to improve performance for repeated
 * period parsing operations.
 *
 */
public class AttributedOnPolicyEvaluator extends AbstractPolicyEvaluator {

    private static final Logger LOGGER = LoggerFactory.getLogger(AttributedOnPolicyEvaluator.class);

    // Cache for parsed periods to avoid repeated parsing overhead
    private static final ConcurrentMap<String, Optional<Period>> PERIOD_CACHE = new ConcurrentHashMap<>();
    private static final int MAX_CACHE_SIZE = 1000;

    // Injectable clock for testing
    private final Clock clock;
    private final ZoneId zoneId;

    /**
     * Default constructor using system clock and default timezone.
     */
    public AttributedOnPolicyEvaluator() {
        this(Clock.systemDefaultZone(), ZoneId.systemDefault());
    }

    /**
     * Constructor with injectable clock and timezone for testing.
     *
     * @param clock  the clock to use for date/time operations
     * @param zoneId the timezone to use for date conversions
     */
    public AttributedOnPolicyEvaluator(final Clock clock, final ZoneId zoneId) {
        this.clock = Objects.requireNonNull(clock, "Clock cannot be null");
        this.zoneId = Objects.requireNonNull(zoneId, "ZoneId cannot be null");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PolicyCondition.Subject supportedSubject() {
        return PolicyCondition.Subject.ATTRIBUTED_ON;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PolicyConditionViolation> evaluate(final Policy policy, final Component component) {
        if (policy == null) {
            LOGGER.debug("Policy is null, returning empty violations list");
            return Collections.emptyList();
        }

        if (component == null) {
            LOGGER.debug("Component is null, returning empty violations list");
            return Collections.emptyList();
        }

        try {
            final List<PolicyCondition> policyConditions = extractSupportedConditions(policy);
            if (policyConditions.isEmpty()) {
                LOGGER.debug("No supported policy conditions found for policy: {}", policy.getName());
                return Collections.emptyList();
            }

            final List<Vulnerability> vulnerabilities = getVulnerabilities(component);
            if (vulnerabilities.isEmpty()) {
                LOGGER.debug("No vulnerabilities found for component: {} ({})",
                        component.getName(), component.getUuid());
                return Collections.emptyList();
            }

            LOGGER.debug("Evaluating {} vulnerabilities against {} policy conditions for component: {} ({})",
                    vulnerabilities.size(), policyConditions.size(), component.getName(), component.getUuid());

            return evaluateVulnerabilities(vulnerabilities, policyConditions, component);

        } catch (final Exception e) {
            LOGGER.error("Unexpected error during policy evaluation for component: {} ({})",
                    component.getName(), component.getUuid(), e);
            return Collections.emptyList();
        }
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
            LOGGER.warn("Failed to retrieve vulnerabilities for component: {} ({})",
                    component.getName(), component.getUuid(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Evaluates vulnerabilities against policy conditions.
     *
     * @param vulnerabilities  the vulnerabilities to evaluate
     * @param policyConditions the policy conditions to check against
     * @param component        the component being evaluated
     * @return list of policy violations
     */
    private List<PolicyConditionViolation> evaluateVulnerabilities(
            final List<Vulnerability> vulnerabilities,
            final List<PolicyCondition> policyConditions,
            final Component component) {

        final List<PolicyConditionViolation> violations = new ArrayList<>();
        int processedVulnerabilities = 0;
        int skippedVulnerabilities = 0;

        for (final Vulnerability vulnerability : vulnerabilities) {
            try {
                final Optional<Date> attributedOnDate = getAttributedOnDate(vulnerability, component);
                if (attributedOnDate.isEmpty()) {
                    skippedVulnerabilities++;
                    continue;
                }

                processedVulnerabilities++;

                for (final PolicyCondition condition : policyConditions) {
                    try {
                        if (evaluateCondition(condition, attributedOnDate.get())) {
                            final PolicyConditionViolation violation = new PolicyConditionViolation(condition, component);
                            violations.add(violation);
                            LOGGER.debug("Policy violation found: vulnerability {} violates condition {} for component {}",
                                    vulnerability.getVulnId(), condition.getUuid(), component.getUuid());
                        }
                    } catch (final Exception e) {
                        LOGGER.warn("Failed to evaluate condition {} for vulnerability {} on component {}: {}",
                                condition.getUuid(), vulnerability.getVulnId(), component.getUuid(), e.getMessage());
                    }
                }
            } catch (final Exception e) {
                LOGGER.warn("Failed to process vulnerability {} for component {}: {}",
                        vulnerability.getVulnId(), component.getUuid(), e.getMessage());
                skippedVulnerabilities++;
            }
        }

        LOGGER.debug("Evaluation complete: {} violations found, {} vulnerabilities processed, {} skipped",
                violations.size(), processedVulnerabilities, skippedVulnerabilities);

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
        if (vulnerability == null) {
            LOGGER.debug("Vulnerability is null, cannot extract attributed on date");
            return Optional.empty();
        }

        try {
            final FindingAttribution attribution = qm.getFindingAttribution(vulnerability, component);
            if (attribution == null) {
                LOGGER.debug("No finding attribution found for vulnerability {} on component {}",
                        vulnerability.getVulnId(), component.getUuid());
                return Optional.empty();
            }

            final Date attributedOn = attribution.getAttributedOn();
            return attributedOn != null ? Optional.of(attributedOn) : Optional.empty();

        } catch (final Exception e) {
            LOGGER.warn("Failed to retrieve finding attribution for vulnerability {} on component {}: {}",
                    vulnerability.getVulnId(), component.getUuid(), e.getMessage());
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
     * @throws DateTimeException if evaluation fails due to invalid data
     */
    private boolean evaluateCondition(final PolicyCondition condition, final Date attributedOn) {
        Objects.requireNonNull(condition, "Policy condition cannot be null");
        Objects.requireNonNull(attributedOn, "Attributed on date cannot be null");

        final Optional<Period> agePeriod = parseAgePeriod(condition);
        if (agePeriod.isEmpty()) {
            LOGGER.warn("Failed to parse age period from condition value: {}", condition.getValue());
            return false;
        }

        if (!isValidAgePeriod(agePeriod.get(), condition.getValue())) {
            LOGGER.warn("Invalid age period in condition: {} (parsed as: {})",
                    condition.getValue(), agePeriod.get());
            return false;
        }

        return evaluateAgeCondition(condition, attributedOn, agePeriod.get());
    }

    /**
     * Parses the age period from the policy condition value with caching.
     *
     * @param condition the policy condition containing the period string
     * @return the parsed period wrapped in Optional, empty if parsing fails
     */
    private Optional<Period> parseAgePeriod(final PolicyCondition condition) {
        final String periodValue = condition.getValue();
        if (periodValue == null || periodValue.trim().isEmpty()) {
            LOGGER.debug("Policy condition value is null or empty");
            return Optional.empty();
        }

        // Check cache first
        Optional<Period> cachedPeriod = PERIOD_CACHE.get(periodValue);
        if (cachedPeriod != null) {
            return cachedPeriod;
        }

        // Parse and cache result
        try {
            final Period period = Period.parse(periodValue.trim());
            cachedPeriod = Optional.of(period);
        } catch (final DateTimeParseException e) {
            LOGGER.debug("Failed to parse period value '{}': {}", periodValue, e.getMessage());
            cachedPeriod = Optional.empty();
        }

        // Cache with size limit
        if (PERIOD_CACHE.size() < MAX_CACHE_SIZE) {
            PERIOD_CACHE.put(periodValue, cachedPeriod);
        }

        return cachedPeriod;
    }

    /**
     * Validates that the age period is positive and non-zero.
     *
     * @param agePeriod     the period to validate
     * @param originalValue the original string value for logging
     * @return true if the period is valid, false otherwise
     */
    private boolean isValidAgePeriod(final Period agePeriod, final String originalValue) {
        if (agePeriod.isZero()) {
            LOGGER.debug("Age period is zero: {}", originalValue);
            return false;
        }

        if (agePeriod.isNegative()) {
            LOGGER.debug("Age period is negative: {}", originalValue);
            return false;
        }

        return true;
    }

    /**
     * Evaluates the age-based condition using the specified operator.
     *
     * @param condition    the policy condition with the operator
     * @param attributedOn the attribution date
     * @param agePeriod    the age period to add to the attribution date
     * @return true if the condition is met, false otherwise
     * @throws DateTimeException if date conversion fails
     */
    private boolean evaluateAgeCondition(final PolicyCondition condition, final Date attributedOn, final Period agePeriod) {
        try {
            final LocalDate attributedOnDate = convertToLocalDate(attributedOn);
            final LocalDate ageDate = attributedOnDate.plus(agePeriod);
            final LocalDate today = LocalDate.now(clock);

            return switch (condition.getOperator()) {
                case NUMERIC_GREATER_THAN -> ageDate.isBefore(today);
                case NUMERIC_GREATER_THAN_OR_EQUAL -> !ageDate.isAfter(today);
                case NUMERIC_EQUAL -> ageDate.isEqual(today);
                case NUMERIC_NOT_EQUAL -> !ageDate.isEqual(today);
                case NUMERIC_LESSER_THAN_OR_EQUAL -> !ageDate.isBefore(today);
                case NUMERIC_LESS_THAN -> ageDate.isAfter(today);
                default -> {
                    LOGGER.warn("Unsupported operator for age-based condition: {}", condition.getOperator());
                    yield false;
                }
            };
        } catch (final DateTimeException e) {
            LOGGER.error("Failed to evaluate age condition: {}", e.getMessage(), e);
            throw new DateTimeException("Date/time evaluation failed", e);
        }
    }

    /**
     * Converts a Date to LocalDate using the configured timezone.
     *
     * @param date the date to convert
     * @return the corresponding LocalDate
     * @throws DateTimeException if conversion fails
     */
    private LocalDate convertToLocalDate(final Date date) {
        try {
            return LocalDate.ofInstant(date.toInstant(), zoneId);
        } catch (final DateTimeException e) {
            LOGGER.error("Failed to convert date to LocalDate: {}", date, e);
            throw e;
        }
    }
}