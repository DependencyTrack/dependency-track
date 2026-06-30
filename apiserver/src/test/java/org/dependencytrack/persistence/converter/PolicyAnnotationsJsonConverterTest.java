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
package org.dependencytrack.persistence.converter;

import org.dependencytrack.model.AppliedPolicyAnnotation;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

class PolicyAnnotationsJsonConverterTest {

    private static final Date APPLIED_AT = Date.from(Instant.parse("2026-01-15T10:30:00Z"));

    @Test
    void roundTripTest() {
        final var annotations = List.of(
                new AppliedPolicyAnnotation("gem-policy", APPLIED_AT, "author-a"),
                new AppliedPolicyAnnotation("csra-policy", APPLIED_AT, "author-b"));

        final String json = PolicyAnnotationsJsonConverter.toJson(annotations);
        assertThat(PolicyAnnotationsJsonConverter.fromJson(json))
                .extracting(
                        AppliedPolicyAnnotation::policyName,
                        AppliedPolicyAnnotation::annotator,
                        AppliedPolicyAnnotation::appliedAt)
                .containsExactly(
                        tuple("gem-policy", "author-a", APPLIED_AT),
                        tuple("csra-policy", "author-b", APPLIED_AT));
    }

    @Test
    void deserializesLegacyKeyValueFormat() {
        final var json = """
                [
                  {
                    "key": "gem",
                    "value": "legacy-policy",
                    "policyName": "legacy-policy",
                    "appliedAt": "2026-01-15T10:30:00Z"
                  }
                ]
                """;

        assertThat(PolicyAnnotationsJsonConverter.fromJson(json))
                .extracting(AppliedPolicyAnnotation::policyName, AppliedPolicyAnnotation::appliedAt)
                .containsExactly(tuple("legacy-policy", APPLIED_AT));
    }

    @Test
    void emptyAndNullJson() {
        assertThat(PolicyAnnotationsJsonConverter.fromJson(null)).isNull();
        assertThat(PolicyAnnotationsJsonConverter.fromJson("")).isNull();
        assertThat(PolicyAnnotationsJsonConverter.toJson(null)).isNull();
        assertThat(PolicyAnnotationsJsonConverter.toJson(List.of())).isNull();
    }

}
