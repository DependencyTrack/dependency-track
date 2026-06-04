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
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

class PolicyAnnotationsJsonConverterTest {

    private static final Instant APPLIED_AT = Instant.parse("2026-01-15T10:30:00Z");

    @Test
    void toJsonAndFromJsonRoundTrip() {
        final var annotations = List.of(
                new AppliedPolicyAnnotation("compliance", "gem", "test-policy", APPLIED_AT),
                new AppliedPolicyAnnotation("source", "astdw-apiservice", "test-policy", APPLIED_AT));

        final String json = PolicyAnnotationsJsonConverter.toJson(annotations);
        assertThatJson(json)
                .isEqualTo("""
                        [
                          {
                            "key": "compliance",
                            "value": "gem",
                            "policyName": "test-policy",
                            "appliedAt": "2026-01-15T10:30:00Z"
                          },
                          {
                            "key": "source",
                            "value": "astdw-apiservice",
                            "policyName": "test-policy",
                            "appliedAt": "2026-01-15T10:30:00Z"
                          }
                        ]
                        """);

        assertThat(PolicyAnnotationsJsonConverter.fromJson(json))
                .extracting(
                        AppliedPolicyAnnotation::key,
                        AppliedPolicyAnnotation::value,
                        AppliedPolicyAnnotation::policyName,
                        AppliedPolicyAnnotation::appliedAt)
                .containsExactly(
                        tuple("compliance", "gem", "test-policy", APPLIED_AT),
                        tuple("source", "astdw-apiservice", "test-policy", APPLIED_AT));
    }

    @Test
    void convertToDatastoreDelegatesToToJson() {
        final var converter = new PolicyAnnotationsJsonConverter();
        final var annotations = List.of(
                new AppliedPolicyAnnotation("compliance", "pci", "policy", APPLIED_AT));

        assertThatJson(converter.convertToDatastore(annotations))
                .isEqualTo("""
                        [
                          {
                            "key": "compliance",
                            "value": "pci",
                            "policyName": "policy",
                            "appliedAt": "2026-01-15T10:30:00Z"
                          }
                        ]
                        """);
    }

    @Test
    void convertToAttributeDelegatesToFromJson() {
        final var converter = new PolicyAnnotationsJsonConverter();

        assertThat(converter.convertToAttribute("""
                [
                  {
                    "key": "owner",
                    "value": "security",
                    "policyName": "annotationPolicy",
                    "appliedAt": "2026-01-15T10:30:00Z"
                  }
                ]
                """))
                .containsExactly(new AppliedPolicyAnnotation(
                        "owner", "security", "annotationPolicy", APPLIED_AT));
    }

    @Test
    void toJsonNullAndEmpty() {
        assertThat(PolicyAnnotationsJsonConverter.toJson(null)).isNull();
        assertThat(PolicyAnnotationsJsonConverter.toJson(List.of())).isNull();
        assertThat(new PolicyAnnotationsJsonConverter().convertToDatastore(null)).isNull();
    }

    @Test
    void fromJsonNullAndBlank() {
        assertThat(PolicyAnnotationsJsonConverter.fromJson(null)).isNull();
        assertThat(PolicyAnnotationsJsonConverter.fromJson("")).isNull();
        assertThat(PolicyAnnotationsJsonConverter.fromJson("  ")).isNull();
        assertThat(new PolicyAnnotationsJsonConverter().convertToAttribute(null)).isNull();
    }

}
