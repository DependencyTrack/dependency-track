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
package org.dependencytrack.vulnanalysis;

import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.model.Severity;
import org.dependencytrack.persistence.jdbi.AnalysisDao.Analysis;
import org.dependencytrack.persistence.jdbi.AnalysisDao.CreateCommentCommand;
import org.dependencytrack.persistence.jdbi.AnalysisDao.MakeAnalysisCommand;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyRating;
import org.dependencytrack.util.AnalysisCommentFormatter;
import org.dependencytrack.util.AnalysisCommentFormatter.AnalysisCommentField;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.common.MdcKeys.MDC_VULN_POLICY_NAME;

/**
 * @since 5.0.0
 */
final class AnalysisReconciler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AnalysisReconciler.class);

    private final long projectId;
    private final long componentId;
    private final long vulnDbId;
    private final @Nullable Long vulnPolicyId;
    private final AnalysisState state;
    private final AnalysisJustification justification;
    private final AnalysisResponse response;
    private final @Nullable String details;
    private final boolean suppressed;
    private final @Nullable Severity severity;
    private final @Nullable String cvssV2Vector;
    private final @Nullable Double cvssV2Score;
    private final @Nullable String cvssV3Vector;
    private final @Nullable Double cvssV3Score;
    private final @Nullable String cvssV4Vector;
    private final @Nullable Double cvssV4Score;
    private final @Nullable String owaspVector;
    private final @Nullable Double owaspScore;

    AnalysisReconciler(
            long projectId,
            long componentId,
            long vulnDbId,
            @Nullable Analysis existing) {
        this.projectId = projectId;
        this.componentId = componentId;
        this.vulnDbId = vulnDbId;
        this.vulnPolicyId = existing != null ? existing.vulnPolicyId() : null;
        this.state = Optional.ofNullable(existing).map(Analysis::state).orElse(AnalysisState.NOT_SET);
        this.justification = Optional.ofNullable(existing).map(Analysis::justification).orElse(AnalysisJustification.NOT_SET);
        this.response = Optional.ofNullable(existing).map(Analysis::response).orElse(AnalysisResponse.NOT_SET);
        this.details = existing != null ? existing.details() : null;
        this.suppressed = existing != null && existing.suppressed();
        this.severity = existing != null ? existing.severity() : null;
        this.cvssV2Vector = existing != null ? existing.cvssV2Vector() : null;
        this.cvssV2Score = existing != null ? existing.cvssV2Score() : null;
        this.cvssV3Vector = existing != null ? existing.cvssV3Vector() : null;
        this.cvssV3Score = existing != null ? existing.cvssV3Score() : null;
        this.cvssV4Vector = existing != null ? existing.cvssV4Vector() : null;
        this.cvssV4Score = existing != null ? existing.cvssV4Score() : null;
        this.owaspVector = existing != null ? existing.owaspVector() : null;
        this.owaspScore = existing != null ? existing.owaspScore() : null;
    }

    @Nullable Result reconcile(VulnerabilityPolicy policy) {
        requireNonNull(policy, "policy must not be null");

        try (var ignoredMdcPolicyName = MDC.putCloseable(MDC_VULN_POLICY_NAME, policy.getName())) {
            final VulnerabilityPolicyAnalysis policyAnalysis = policy.getAnalysis();
            if (policyAnalysis == null) {
                LOGGER.warn("Vulnerability policy does not define an analysis");
                return null;
            }

            final AnalysisState desiredState = switch (policyAnalysis.getState()) {
                case EXPLOITABLE -> AnalysisState.EXPLOITABLE;
                case FALSE_POSITIVE -> AnalysisState.FALSE_POSITIVE;
                case IN_TRIAGE -> AnalysisState.IN_TRIAGE;
                case NOT_AFFECTED -> AnalysisState.NOT_AFFECTED;
                case RESOLVED -> AnalysisState.RESOLVED;
                case null -> AnalysisState.NOT_SET;
            };
            final AnalysisJustification desiredJustification = switch (policyAnalysis.getJustification()) {
                case CODE_NOT_PRESENT -> AnalysisJustification.CODE_NOT_PRESENT;
                case CODE_NOT_REACHABLE -> AnalysisJustification.CODE_NOT_REACHABLE;
                case PROTECTED_AT_PERIMETER -> AnalysisJustification.PROTECTED_AT_PERIMETER;
                case PROTECTED_AT_RUNTIME -> AnalysisJustification.PROTECTED_AT_RUNTIME;
                case PROTECTED_BY_COMPILER -> AnalysisJustification.PROTECTED_BY_COMPILER;
                case PROTECTED_BY_MITIGATING_CONTROL -> AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL;
                case REQUIRES_CONFIGURATION -> AnalysisJustification.REQUIRES_CONFIGURATION;
                case REQUIRES_DEPENDENCY -> AnalysisJustification.REQUIRES_DEPENDENCY;
                case REQUIRES_ENVIRONMENT -> AnalysisJustification.REQUIRES_ENVIRONMENT;
                case null -> AnalysisJustification.NOT_SET;
            };
            final AnalysisResponse desiredResponse = switch (policyAnalysis.getVendorResponse()) {
                case CAN_NOT_FIX -> AnalysisResponse.CAN_NOT_FIX;
                case ROLLBACK -> AnalysisResponse.ROLLBACK;
                case UPDATE -> AnalysisResponse.UPDATE;
                case WILL_NOT_FIX -> AnalysisResponse.WILL_NOT_FIX;
                case WORKAROUND_AVAILABLE -> AnalysisResponse.WORKAROUND_AVAILABLE;
                case null -> AnalysisResponse.NOT_SET;
            };
            final String desiredDetails = policyAnalysis.getDetails();
            final boolean desiredSuppressed = policyAnalysis.isSuppress();

            Severity desiredSeverity = null;
            String desiredCvssV2Vector = null;
            Double desiredCvssV2Score = null;
            String desiredCvssV3Vector = null;
            Double desiredCvssV3Score = null;
            String desiredCvssV4Vector = null;
            Double desiredCvssV4Score = null;
            String desiredOwaspVector = null;
            Double desiredOwaspScore = null;

            if (policy.getRatings() != null) {
                final var methodsSeen = new HashSet<VulnerabilityPolicyRating.Method>();

                for (int i = 0; i < policy.getRatings().size(); i++) {
                    final VulnerabilityPolicyRating rating = policy.getRatings().get(i);

                    if (rating.getMethod() == null) {
                        LOGGER.warn("Rating #{} does not define a method; Skipping", i);
                        continue;
                    }
                    if (rating.getSeverity() == null) {
                        LOGGER.warn("Rating #{} does not define a severity; Skipping", i);
                        continue;
                    }
                    if (!methodsSeen.add(rating.getMethod())) {
                        LOGGER.debug("Method of rating #{} already seen; Skipping", i);
                        continue;
                    }

                    // Retain the highest severity among all ratings.
                    final Severity ratingSeverity = switch (rating.getSeverity()) {
                        case INFO -> Severity.INFO;
                        case LOW -> Severity.LOW;
                        case MEDIUM -> Severity.MEDIUM;
                        case HIGH -> Severity.HIGH;
                        case CRITICAL -> Severity.CRITICAL;
                    };
                    if (desiredSeverity == null || ratingSeverity.getLevel() > desiredSeverity.getLevel()) {
                        desiredSeverity = ratingSeverity;
                    }

                    switch (rating.getMethod()) {
                        case CVSSV2 -> {
                            desiredCvssV2Vector = rating.getVector();
                            desiredCvssV2Score = rating.getScore();
                        }
                        case CVSSV3 -> {
                            desiredCvssV3Vector = rating.getVector();
                            desiredCvssV3Score = rating.getScore();
                        }
                        case CVSSV4 -> {
                            desiredCvssV4Vector = rating.getVector();
                            desiredCvssV4Score = rating.getScore();
                        }
                        case OWASP -> {
                            desiredOwaspVector = rating.getVector();
                            desiredOwaspScore = rating.getScore();
                        }
                    }
                }
            }

            final String commenter;
            if (policy.getAuthor() != null) {
                commenter = "[Policy{Name=%s, Author=%s}]".formatted(policy.getName(), policy.getAuthor());
            } else {
                commenter = "[Policy{Name=%s}]".formatted(policy.getName());
            }

            final var comments = new ArrayList<String>();
            boolean hasChanged = false;

            final boolean analysisStateChanged = diffField(comments, AnalysisCommentField.STATE, state, desiredState);
            hasChanged |= analysisStateChanged;
            hasChanged |= diffField(comments, AnalysisCommentField.JUSTIFICATION, justification, desiredJustification);
            hasChanged |= diffField(comments, AnalysisCommentField.RESPONSE, response, desiredResponse);
            hasChanged |= diffField(comments, AnalysisCommentField.DETAILS, details, desiredDetails);
            final boolean suppressionChanged = diffField(comments, AnalysisCommentField.SUPPRESSED, suppressed, desiredSuppressed);
            hasChanged |= suppressionChanged;
            hasChanged |= diffField(comments, AnalysisCommentField.SEVERITY, severity, desiredSeverity);
            hasChanged |= diffField(comments, AnalysisCommentField.CVSSV2_VECTOR, cvssV2Vector, desiredCvssV2Vector);
            hasChanged |= diffField(comments, AnalysisCommentField.CVSSV2_SCORE, cvssV2Score, desiredCvssV2Score);
            hasChanged |= diffField(comments, AnalysisCommentField.CVSSV3_VECTOR, cvssV3Vector, desiredCvssV3Vector);
            hasChanged |= diffField(comments, AnalysisCommentField.CVSSV3_SCORE, cvssV3Score, desiredCvssV3Score);
            hasChanged |= diffField(comments, AnalysisCommentField.CVSSV4_VECTOR, cvssV4Vector, desiredCvssV4Vector);
            hasChanged |= diffField(comments, AnalysisCommentField.CVSSV4_SCORE, cvssV4Score, desiredCvssV4Score);
            hasChanged |= diffField(comments, AnalysisCommentField.OWASP_VECTOR, owaspVector, desiredOwaspVector);
            hasChanged |= diffField(comments, AnalysisCommentField.OWASP_SCORE, owaspScore, desiredOwaspScore);

            if (!hasChanged) {
                return null;
            }

            final var command = new MakeAnalysisCommand(
                    this.projectId,
                    this.componentId,
                    this.vulnDbId,
                    policy.getName(),
                    desiredState,
                    desiredJustification,
                    desiredResponse,
                    desiredDetails,
                    desiredSuppressed,
                    desiredSeverity,
                    desiredCvssV2Vector,
                    desiredCvssV2Score,
                    desiredCvssV3Vector,
                    desiredCvssV3Score,
                    desiredCvssV4Vector,
                    desiredCvssV4Score,
                    desiredOwaspVector,
                    desiredOwaspScore);

            if (policy.getCondition() != null && !policy.getCondition().isEmpty()) {
                comments.addFirst("Matched on condition: " + policy.getCondition());
            }

            return new Result(
                    new FindingKey(componentId, vulnDbId),
                    command,
                    commenter,
                    comments,
                    analysisStateChanged,
                    suppressionChanged);
        }
    }

    @Nullable Result reconcileForNoPolicy() {
        final var comments = new ArrayList<String>();
        boolean hasChanged = false;

        final boolean analysisStateChanged = diffField(comments, AnalysisCommentField.STATE, state, AnalysisState.NOT_SET);
        hasChanged |= analysisStateChanged;
        hasChanged |= diffField(comments, AnalysisCommentField.JUSTIFICATION, justification, AnalysisJustification.NOT_SET);
        hasChanged |= diffField(comments, AnalysisCommentField.RESPONSE, response, AnalysisResponse.NOT_SET);
        hasChanged |= diffField(comments, AnalysisCommentField.DETAILS, details, null);
        final boolean suppressionChanged = diffField(comments, AnalysisCommentField.SUPPRESSED, suppressed, false);
        hasChanged |= suppressionChanged;
        hasChanged |= diffField(comments, AnalysisCommentField.SEVERITY, severity, null);
        hasChanged |= diffField(comments, AnalysisCommentField.CVSSV2_VECTOR, cvssV2Vector, null);
        hasChanged |= diffField(comments, AnalysisCommentField.CVSSV2_SCORE, cvssV2Score, null);
        hasChanged |= diffField(comments, AnalysisCommentField.CVSSV3_VECTOR, cvssV3Vector, null);
        hasChanged |= diffField(comments, AnalysisCommentField.CVSSV3_SCORE, cvssV3Score, null);
        hasChanged |= diffField(comments, AnalysisCommentField.CVSSV4_VECTOR, cvssV4Vector, null);
        hasChanged |= diffField(comments, AnalysisCommentField.CVSSV4_SCORE, cvssV4Score, null);
        hasChanged |= diffField(comments, AnalysisCommentField.OWASP_VECTOR, owaspVector, null);
        hasChanged |= diffField(comments, AnalysisCommentField.OWASP_SCORE, owaspScore, null);

        if (this.vulnPolicyId != null) {
            hasChanged = true;
        }

        if (!hasChanged) {
            return null;
        }

        final var command = new MakeAnalysisCommand(
                this.projectId,
                this.componentId,
                this.vulnDbId,
                null,
                AnalysisState.NOT_SET,
                AnalysisJustification.NOT_SET,
                AnalysisResponse.NOT_SET,
                null,
                false,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);

        comments.addFirst("No longer covered by any policy");

        return new Result(
                new FindingKey(componentId, vulnDbId),
                command,
                "[Policy{None}]",
                comments,
                analysisStateChanged,
                suppressionChanged);
    }

    private static boolean diffField(
            List<String> comments,
            AnalysisCommentField field,
            @Nullable Object oldValue,
            @Nullable Object newValue) {
        if (!Objects.equals(oldValue, newValue)) {
            comments.add(AnalysisCommentFormatter.formatComment(field, oldValue, newValue));
            return true;
        }

        return false;
    }

    record Result(
            FindingKey findingKey,
            MakeAnalysisCommand makeAnalysisCommand,
            String commenter,
            List<String> comments,
            boolean analysisStateChanged,
            boolean suppressionChanged) {

        List<CreateCommentCommand> createCommentCommands(long analysisId) {
            return comments.stream()
                    .map(comment -> new CreateCommentCommand(analysisId, commenter, comment))
                    .toList();
        }
    }

}
