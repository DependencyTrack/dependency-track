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
package org.dependencytrack.v4migrator.config;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import picocli.CommandLine.TypeConversionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SchemaNameConverterTest {

    private final SchemaNameConverter converter = new SchemaNameConverter();

    @ParameterizedTest
    @ValueSource(strings = {
        "public",
        "dbo",
        "_dt",
        "DependencyTrack",
        "a$b",
        "x1",
        "dt_v4_migration",
        "custom-schema",
        "with-dash",
        "with.dot",
        "with space",
        " ",
        "1leading_digit",
        "with;semicolon",
        "foo;DROP TABLE x"
    })
    void shouldAcceptValidName(final String value) {
        assertThat(converter.convert(value)).isEqualTo(value);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "with\"quote",
        "with'apostrophe",
        "foo'); DROP TABLE x;--",
        "with\ttab",
        "with\nnewline",
        "a234567890123456789012345678901234567890123456789012345678901234"
    })
    void shouldRejectInvalidName(final String value) {
        assertThatThrownBy(() -> converter.convert(value))
            .isInstanceOf(TypeConversionException.class);
    }
}
