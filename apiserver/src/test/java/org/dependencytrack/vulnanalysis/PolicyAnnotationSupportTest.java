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
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.dependencytrack.vulnanalysis.PolicyAnnotationSupport.annotationsEqual;
import static org.dependencytrack.vulnanalysis.PolicyAnnotationSupport.desiredAnnotationsFromPolicies;
import static org.dependencytrack.vulnanalysis.PolicyAnnotationSupport.formatAnnotations;

class PolicyAnnotationSupportTest {

    @Test
    void annotationsEqualIgnoresAppliedAtAndAnnotator() {
        final var existing = List.of(
                new AppliedPolicyAnnotation("test-policy", Date.from(Instant.parse("2020-01-01T00:00:00Z")), "author-a"));
        final var desired = List.of(
                new AppliedPolicyAnnotation("test-policy", Date.from(Instant.parse("2026-01-01T00:00:00Z")), "author-b"));

        assertThat(annotationsEqual(existing, desired)).isTrue();
    }

    @Test
    void annotationsEqualDetectsPolicyNameChanges() {
        final var existing = List.of(
                new AppliedPolicyAnnotation("gem-policy", Date.from(Instant.now()), "author"));
        final var desired = List.of(
                new AppliedPolicyAnnotation("csra-policy", Date.from(Instant.now()), "author"));

        assertThat(annotationsEqual(existing, desired)).isFalse();
    }

    @Test
    void desiredAnnotationsFromPoliciesMergesAllMatches() {
        final var gemPolicy = new VulnerabilityPolicy();
        gemPolicy.setName("gem-policy");
        gemPolicy.setAuthor("author-gem");
        final var gemAnalysis = new VulnerabilityPolicyAnalysis();
        gemAnalysis.setAnnotations(List.of(new PolicyAnnotation("gem", "gem")));
        gemPolicy.setAnalysis(gemAnalysis);

        final var csraPolicy = new VulnerabilityPolicy();
        csraPolicy.setName("csra-policy");
        csraPolicy.setAuthor("author-csra");
        final var csraAnalysis = new VulnerabilityPolicyAnalysis();
        csraAnalysis.setAnnotations(List.of(new PolicyAnnotation("gem", "csra")));
        csraPolicy.setAnalysis(csraAnalysis);

        assertThat(desiredAnnotationsFromPolicies(List.of(gemPolicy, csraPolicy)))
                .extracting(
                        AppliedPolicyAnnotation::policyName,
                        AppliedPolicyAnnotation::annotator)
                .containsExactly(
                        tuple("gem-policy", "author-gem"),
                        tuple("csra-policy", "author-csra"));
    }

    @Test
    void policyCommenterUsesPolicyNameOnly() {
        assertThat(PolicyAnnotationSupport.policyCommenter("gem-policy")).isEqualTo("gem-policy");
    }

    @Test
    void annotationAuditCommentsOnFirstApplyCreatesEntryPerPolicy() {
        final var gemA = new AppliedPolicyAnnotation("gem-policy-a", Date.from(Instant.now()), "author-a");
        final var gemB = new AppliedPolicyAnnotation("gem-policy-b", Date.from(Instant.now()), "author-b");

        assertThat(PolicyAnnotationSupport.annotationAuditComments(null, List.of(gemA, gemB), "Policy"))
                .extracting(
                        PolicyAnnotationSupport.AnnotationAuditComment::commenter,
                        PolicyAnnotationSupport.AnnotationAuditComment::comment)
                .containsExactly(
                        tuple("gem-policy-a", "Policy annotations: (None) → [gem-policy-a (author-a)]"),
                        tuple("gem-policy-b", "Policy annotations: (None) → [gem-policy-b (author-b)]"));
    }

    @Test
    void annotationAuditCommentsOnChangeUsesCombinedDiff() {
        final var existing = List.of(new AppliedPolicyAnnotation("gem-policy-a", Date.from(Instant.now()), "author-a"));
        final var desired = List.of(
                new AppliedPolicyAnnotation("gem-policy-a", Date.from(Instant.now()), "author-a"),
                new AppliedPolicyAnnotation("gem-policy-b", Date.from(Instant.now()), "author-b"));

        assertThat(PolicyAnnotationSupport.annotationAuditComments(existing, desired, "owner-policy"))
                .extracting(
                        PolicyAnnotationSupport.AnnotationAuditComment::commenter,
                        PolicyAnnotationSupport.AnnotationAuditComment::comment)
                .containsExactly(tuple(
                        "owner-policy",
                        "Policy annotations: [gem-policy-a (author-a)] → [gem-policy-a (author-a), gem-policy-b (author-b)]"));
    }

    @Test
    void hasExistingAnnotationsDetectsEmpty() {
        assertThat(PolicyAnnotationSupport.hasExistingAnnotations(null)).isFalse();
        assertThat(PolicyAnnotationSupport.hasExistingAnnotations(List.of())).isFalse();
        assertThat(PolicyAnnotationSupport.hasExistingAnnotations(List.of(
                new AppliedPolicyAnnotation("gem-policy", Date.from(Instant.now()), "author")))).isTrue();
    }

    @Test
    void desiredAnnotationsFromPoliciesUsesPolicyNameAndAuthor() {
        final var policy = new VulnerabilityPolicy();
        policy.setName("test-policy");
        policy.setAuthor("policy-author");

        final var policyAnalysis = new VulnerabilityPolicyAnalysis();
        policyAnalysis.setAnnotations(List.of(new PolicyAnnotation("ignored", "ignored")));
        policy.setAnalysis(policyAnalysis);

        final List<AppliedPolicyAnnotation> desired = desiredAnnotationsFromPolicies(List.of(policy));

        assertThat(desired).hasSize(1);
        assertThat(desired.getFirst())
                .extracting(
                        AppliedPolicyAnnotation::policyName,
                        AppliedPolicyAnnotation::annotator)
                .containsExactly("test-policy", "policy-author");
    }

    @Test
    void formatAnnotatorForAuditUsesLocalPartOfEmail() {
        assertThat(PolicyAnnotationSupport.formatAnnotatorForAudit("jane.doe@security.example.com"))
                .isEqualTo("jane.doe");
        assertThat(PolicyAnnotationSupport.formatAnnotatorForAudit("Security Team"))
                .isEqualTo("Security Team");
        assertThat(PolicyAnnotationSupport.formatAnnotatorForAudit(null)).isNull();
    }

    @Test
    void formatAnnotationsTest() {
        assertThat(formatAnnotations(null)).isEqualTo("(None)");
        assertThat(formatAnnotations(List.of(
                new AppliedPolicyAnnotation("gem-policy", Date.from(Instant.now()), "security@example.com"))))
                .isEqualTo("[gem-policy (security)]");
        assertThat(formatAnnotations(List.of(
                new AppliedPolicyAnnotation("gem-policy", Date.from(Instant.now()), "Security Team"))))
                .isEqualTo("[gem-policy (Security Team)]");
    }

}
