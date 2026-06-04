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
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.dependencytrack.vulnanalysis.PolicyAnnotationSupport.annotationsEqual;
import static org.dependencytrack.vulnanalysis.PolicyAnnotationSupport.desiredAnnotations;
import static org.dependencytrack.vulnanalysis.PolicyAnnotationSupport.formatAnnotations;

class PolicyAnnotationSupportTest {

    @Test
    void annotationsEqualIgnoresMetadata() {
        final var existing = List.of(
                new AppliedPolicyAnnotation("compliance", "pci", "old-policy", Instant.parse("2020-01-01T00:00:00Z")));
        final var desired = List.of(
                new AppliedPolicyAnnotation("compliance", "pci", "new-policy", Instant.parse("2026-01-01T00:00:00Z")));

        assertThat(annotationsEqual(existing, desired)).isTrue();
    }

    @Test
    void annotationsEqualDetectsKeyValueChanges() {
        final var existing = List.of(
                new AppliedPolicyAnnotation("compliance", "pci", "policy", Instant.now()));
        final var desired = List.of(
                new AppliedPolicyAnnotation("compliance", "sox", "policy", Instant.now()));

        assertThat(annotationsEqual(existing, desired)).isFalse();
    }

    @Test
    void desiredAnnotationsSkipsBlankKeys() {
        final var policy = new VulnerabilityPolicy();
        policy.setName("test-policy");

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setAnnotations(List.of(
                new PolicyAnnotation("compliance", "pci"),
                new PolicyAnnotation("  ", "ignored"),
                new PolicyAnnotation("owner", null)));

        final List<AppliedPolicyAnnotation> desired = desiredAnnotations(policy, policyAnalysis);

        assertThat(desired).hasSize(2);
        assertThat(desired)
                .extracting(AppliedPolicyAnnotation::key, AppliedPolicyAnnotation::value, AppliedPolicyAnnotation::policyName)
                .containsExactly(
                        tuple("compliance", "pci", "test-policy"),
                        tuple("owner", null, "test-policy"));
    }

    @Test
    void formatAnnotationsTest() {
        assertThat(formatAnnotations(null)).isEqualTo("(None)");
        assertThat(formatAnnotations(List.of(
                new AppliedPolicyAnnotation("owner", "security", "policy", Instant.now()))))
                .isEqualTo("[owner=security]");
    }

}
