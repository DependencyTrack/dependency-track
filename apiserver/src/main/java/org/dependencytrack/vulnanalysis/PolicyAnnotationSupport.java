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
import org.dependencytrack.model.PolicyAnnotation;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

final class PolicyAnnotationSupport {

    private PolicyAnnotationSupport() {
    }

    static List<AppliedPolicyAnnotation> desiredAnnotations(
            final VulnerabilityPolicy policy,
            final VulnerabilityPolicyAnalysis policyAnalysis) {
        if (policyAnalysis.getAnnotations() == null || policyAnalysis.getAnnotations().isEmpty()) {
            return List.of();
        }

        final Instant appliedAt = Instant.now();
        final var desired = new ArrayList<AppliedPolicyAnnotation>();
        for (final PolicyAnnotation annotation : policyAnalysis.getAnnotations()) {
            if (annotation == null || annotation.key() == null || annotation.key().isBlank()) {
                continue;
            }
            desired.add(new AppliedPolicyAnnotation(
                    annotation.key(),
                    annotation.value(),
                    policy.getName(),
                    appliedAt));
        }
        return List.copyOf(desired);
    }

    static boolean annotationsEqual(
            @Nullable List<AppliedPolicyAnnotation> existing,
            @Nullable List<AppliedPolicyAnnotation> desired) {
        return normalizedKeyValues(existing).equals(normalizedKeyValues(desired));
    }

    static String formatAnnotations(@Nullable List<AppliedPolicyAnnotation> annotations) {
        if (annotations == null || annotations.isEmpty()) {
            return "(None)";
        }

        return annotations.stream()
                .sorted(Comparator.comparing(AppliedPolicyAnnotation::key))
                .map(annotation -> {
                    if (annotation.value() == null || annotation.value().isBlank()) {
                        return annotation.key();
                    }
                    return "%s=%s".formatted(annotation.key(), annotation.value());
                })
                .collect(Collectors.joining(", ", "[", "]"));
    }

    private static List<String> normalizedKeyValues(@Nullable List<AppliedPolicyAnnotation> annotations) {
        if (annotations == null || annotations.isEmpty()) {
            return List.of();
        }

        return annotations.stream()
                .filter(Objects::nonNull)
                .filter(annotation -> annotation.key() != null && !annotation.key().isBlank())
                .map(annotation -> annotation.key() + "\0" + Objects.toString(annotation.value(), ""))
                .sorted()
                .toList();
    }

}
