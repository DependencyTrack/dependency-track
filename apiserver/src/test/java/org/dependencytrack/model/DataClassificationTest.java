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

import org.dependencytrack.model.DataClassification.Direction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class DataClassificationTest {

    private static Stream<Arguments> equalsAndHashCodeShouldCompareByValue() {
        return Stream.of(
                arguments(
                        new DataClassification(Direction.INBOUND, "public"),
                        new DataClassification(Direction.INBOUND, "public"),
                        true),
                arguments(
                        new DataClassification(null, null),
                        new DataClassification(null, null),
                        true),
                arguments(
                        new DataClassification(Direction.INBOUND, "public"),
                        new DataClassification(Direction.OUTBOUND, "public"),
                        false),
                arguments(
                        new DataClassification(Direction.INBOUND, "public"),
                        new DataClassification(Direction.INBOUND, "private"),
                        false),
                arguments(
                        new DataClassification(Direction.INBOUND, "public"),
                        new DataClassification(null, "public"),
                        false),
                arguments(
                        new DataClassification(Direction.INBOUND, "public"),
                        new DataClassification(Direction.INBOUND, null),
                        false));
    }

    @ParameterizedTest
    @MethodSource
    void equalsAndHashCodeShouldCompareByValue(
            DataClassification left,
            DataClassification right,
            boolean expectEqual) {
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
        final DataClassification dataClassification = new DataClassification(Direction.INBOUND, "public");

        assertThat(dataClassification).isEqualTo(dataClassification);
    }

    @Test
    void equalsShouldNotMatchNullOrOtherTypes() {
        final DataClassification dataClassification = new DataClassification(Direction.INBOUND, "public");

        assertThat(dataClassification).isNotEqualTo(null);
        assertThat(dataClassification).isNotEqualTo("public");
    }

}
