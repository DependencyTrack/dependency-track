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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GlobalOptionsTest {

    @Test
    void acceptsDefaultAndOtherSafeIdentifiers() {
        assertThatCode(() -> options("dt_v4_migration").validate()).doesNotThrowAnyException();
        assertThatCode(() -> options("MyStaging").validate()).doesNotThrowAnyException();
        assertThatCode(() -> options("_underscore_start$").validate()).doesNotThrowAnyException();
    }

    @Test
    void rejectsInjectionVectors() {
        assertThatThrownBy(() -> options("dt; DROP TABLE \"PROJECT\"; --").validate())
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> options("\"injected\"").validate())
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> options("a-b").validate())
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> options("9starts_with_digit").validate())
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsEmptyNullAndOverLength() {
        assertThatThrownBy(() -> options("").validate()).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> options(null).validate()).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> options("a".repeat(64)).validate())
            .isInstanceOf(IllegalArgumentException.class);
    }

    private static GlobalOptions options(final String schema) {
        final GlobalOptions o = new GlobalOptions();
        o.stagingSchema = schema;
        return o;
    }
}
