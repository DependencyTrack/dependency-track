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

import org.dependencytrack.model.AppliedPolicyAnnotation;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.dependencytrack.util.AnalysisCommentFormatter;
import org.dependencytrack.util.AnalysisCommentFormatter.AnalysisCommentField;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.isBlank;

public final class PolicyAnnotationSupport {

    public record AnnotationAuditComment(String commenter, String comment) {
    }

    private PolicyAnnotationSupport() {
    }

    public static List<AppliedPolicyAnnotation> desiredAnnotationsFromPolicies(
            final List<VulnerabilityPolicy> policies) {
        if (policies == null || policies.isEmpty()) {
            return List.of();
        }

        final var desired = new ArrayList<AppliedPolicyAnnotation>();
        final var seenPolicyNames = new HashSet<String>();
        for (final VulnerabilityPolicy policy : policies) {
            if (policy == null || policy.getAnalysis() == null) {
                continue;
            }
            if (!hasAnnotationDefinitions(policy.getAnalysis())) {
                continue;
            }
            if (!seenPolicyNames.add(policy.getName())) {
                continue;
            }
            desired.add(desiredAnnotationForPolicy(policy));
        }
        return List.copyOf(desired);
    }

    public static boolean annotationsEqual(
            @Nullable List<AppliedPolicyAnnotation> existing,
            @Nullable List<AppliedPolicyAnnotation> desired) {
        return normalizedPolicyNames(existing).equals(normalizedPolicyNames(desired));
    }

    static boolean hasExistingAnnotations(@Nullable final List<AppliedPolicyAnnotation> annotations) {
        return annotations != null && !annotations.isEmpty();
    }

    /**
     * Builds audit comments for annotation changes. On first apply, each matching policy gets its own
     * comment (with that policy as commenter). On subsequent changes, a single combined diff is used.
     */
    public static List<AnnotationAuditComment> annotationAuditComments(
            @Nullable final List<AppliedPolicyAnnotation> existing,
            @Nullable final List<AppliedPolicyAnnotation> desired,
            final String changeCommenter) {
        if (annotationsEqual(existing, desired)) {
            return List.of();
        }

        if (!hasExistingAnnotations(existing)) {
            if (desired == null || desired.isEmpty()) {
                return List.of();
            }

            return desired.stream()
                    .sorted(Comparator.comparing(
                            AppliedPolicyAnnotation::policyName,
                            Comparator.nullsFirst(String::compareTo)))
                    .map(annotation -> new AnnotationAuditComment(
                            policyCommenter(annotation.policyName()),
                            AnalysisCommentFormatter.formatComment(
                                    AnalysisCommentField.POLICY_ANNOTATIONS,
                                    "(None)",
                                    formatAnnotations(List.of(annotation)))))
                    .toList();
        }

        return List.of(new AnnotationAuditComment(
                changeCommenter,
                AnalysisCommentFormatter.formatComment(
                        AnalysisCommentField.POLICY_ANNOTATIONS,
                        formatAnnotations(existing),
                        formatAnnotations(desired))));
    }

    public static String policyCommenter(final String policyName) {
        return policyName;
    }

    /**
     * Shortens policy author for human-readable audit comments. Email addresses are reduced to
     * their local part; other values (e.g. display names) are kept as-is. The full author is
     * still stored on {@link AppliedPolicyAnnotation#annotator()}.
     */
    public static String formatAnnotatorForAudit(@Nullable final String annotator) {
        if (isBlank(annotator)) {
            return null;
        }
        final String trimmed = annotator.trim();
        final int atIndex = trimmed.indexOf('@');
        if (atIndex > 0) {
            return trimmed.substring(0, atIndex);
        }
        return trimmed;
    }

    public static String formatAnnotations(@Nullable List<AppliedPolicyAnnotation> annotations) {
        if (annotations == null || annotations.isEmpty()) {
            return "(None)";
        }

        return annotations.stream()
                .sorted(Comparator.comparing(
                        AppliedPolicyAnnotation::policyName,
                        Comparator.nullsFirst(String::compareTo)))
                .map(PolicyAnnotationSupport::formatAnnotation)
                .collect(Collectors.joining(", ", "[", "]"));
    }

    private static AppliedPolicyAnnotation desiredAnnotationForPolicy(final VulnerabilityPolicy policy) {
        return new AppliedPolicyAnnotation(
                policy.getName(),
                Instant.now(),
                policy.getAuthor());
    }

    private static boolean hasAnnotationDefinitions(final VulnerabilityPolicyAnalysis policyAnalysis) {
        return policyAnalysis.getAnnotations() != null && !policyAnalysis.getAnnotations().isEmpty();
    }

    private static String formatAnnotation(final AppliedPolicyAnnotation annotation) {
        final String annotator = formatAnnotatorForAudit(annotation.annotator());
        if (isBlank(annotator)) {
            return annotation.policyName();
        }
        return "%s (%s)".formatted(annotation.policyName(), annotator);
    }

    private static List<String> normalizedPolicyNames(@Nullable List<AppliedPolicyAnnotation> annotations) {
        if (annotations == null || annotations.isEmpty()) {
            return List.of();
        }

        return annotations.stream()
                .filter(Objects::nonNull)
                .map(AppliedPolicyAnnotation::policyName)
                .filter(name -> !isBlank(name))
                .sorted()
                .toList();
    }

}
