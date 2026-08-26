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
package org.dependencytrack.model;

import org.cyclonedx.model.ExternalReference.Type;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ExternalReferenceTest {

    private static Stream<Arguments> equalsAndHashCodeShouldCompareByValue() {
        return Stream.of(
                arguments(
                        new ExternalReference(Type.WEBSITE, "https://example.com", "comment"),
                        new ExternalReference(Type.WEBSITE, "https://example.com", "comment"),
                        true),
                arguments(new ExternalReference(null, null, null), new ExternalReference(null, null, null), true),
                arguments(
                        new ExternalReference(Type.WEBSITE, "https://example.com", "comment"),
                        new ExternalReference(Type.VCS, "https://example.com", "comment"),
                        false),
                arguments(
                        new ExternalReference(Type.WEBSITE, "https://example.com", "comment"),
                        new ExternalReference(Type.WEBSITE, "https://example.org", "comment"),
                        false),
                arguments(
                        new ExternalReference(Type.WEBSITE, "https://example.com", "comment"),
                        new ExternalReference(Type.WEBSITE, "https://example.com", "other comment"),
                        false),
                arguments(
                        new ExternalReference(Type.WEBSITE, "https://example.com", "comment"),
                        new ExternalReference(null, "https://example.com", "comment"),
                        false),
                arguments(
                        new ExternalReference(Type.WEBSITE, "https://example.com", "comment"),
                        new ExternalReference(Type.WEBSITE, null, "comment"),
                        false),
                arguments(
                        new ExternalReference(Type.WEBSITE, "https://example.com", "comment"),
                        new ExternalReference(Type.WEBSITE, "https://example.com", null),
                        false));
    }

    @ParameterizedTest
    @MethodSource
    void equalsAndHashCodeShouldCompareByValue(ExternalReference left, ExternalReference right, boolean expectEqual) {
        if (expectEqual) {
            assertThat(left).isEqualTo(right);
            assertThat(right).isEqualTo(left);
            assertThat(left).hasSameHashCodeAs(right);
        } else {
            assertThat(left).isNotEqualTo(right);
            assertThat(right).isNotEqualTo(left);
            assertThat(left.hashCode()).isNotEqualTo(right.hashCode());
        }
    }

    @Test
    void equalsShouldBeReflexive() {
        final ExternalReference externalReference =
                new ExternalReference(Type.WEBSITE, "https://example.com", "comment");

        assertThat(externalReference).isEqualTo(externalReference);
    }

    @Test
    void equalsShouldNotMatchNullOrOtherTypes() {
        final ExternalReference externalReference =
                new ExternalReference(Type.WEBSITE, "https://example.com", "comment");

        assertThat(externalReference).isNotEqualTo(null);
        assertThat(externalReference).isNotEqualTo("https://example.com");
    }
}
