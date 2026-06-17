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
package org.dependencytrack.parser.spdx.expression;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class SpdxExpressionsTest {

    @Nested
    class AllowsTest {

        // NB: Some test cases were sourced from https://github.com/github/go-spdx/blob/main/spdxexp/satisfies_test.go.
        // There doesn't appear to be an official comprehensive test suite.
        private static Stream<Arguments> shouldEvaluateArgs() {
            return Stream.of(
                    Arguments.of("MIT", List.of("MIT"), true),
                    Arguments.of("miT", List.of("MIT"), true),
                    Arguments.of("MIT", List.of("mit"), true),
                    Arguments.of("GPL-2.0+", List.of("GPL-2.0"), true),
                    Arguments.of("MIT", List.of("MIT", "Apache-2.0"), true),
                    Arguments.of("MIT OR Apache-2.0", List.of("MIT"), true),
                    Arguments.of("MIT OR GPL-3.0", List.of("MIT"), true),
                    Arguments.of("Apache-2.0 AND MIT", List.of("MIT", "APACHE-2.0"), true),
                    Arguments.of("apache-2.0 AND mit", List.of("MIT", "APACHE-2.0"), true),
                    Arguments.of("MIT AND Apache-2.0", List.of("MIT", "Apache-2.0"), true),
                    Arguments.of("MIT AND BSD-3-Clause", List.of("MIT", "BSD-3-Clause"), true),
                    Arguments.of("MIT AND Apache-2.0", List.of("MIT", "Apache-1.0", "Apache-2.0"), true),
                    Arguments.of("GPL-2.0 WITH Classpath-exception-2.0", List.of("GPL-2.0 WITH Classpath-exception-2.0"), true),
                    Arguments.of("GPL-2.0 WITH Classpath-exception-2.0", List.of("GPL-2.0", "Classpath-exception-2.0"), false),
                    Arguments.of("(MIT OR GPL-2.0)", List.of("ISC", "MIT"), true),
                    Arguments.of("(MIT AND GPL-2.0)", List.of("MIT", "GPL-2.0"), true),
                    Arguments.of("(MIT AND GPL-2.0)", List.of("GPL-2.0", "MIT"), true),
                    Arguments.of("MIT AND GPL-2.0 AND ISC", List.of("MIT", "GPL-2.0", "ISC"), true),
                    Arguments.of("MIT AND GPL-2.0 AND ISC", List.of("ISC", "GPL-2.0", "MIT"), true),
                    Arguments.of("(MIT OR GPL-2.0) AND ISC", List.of("MIT", "ISC"), true),
                    Arguments.of("MIT AND ISC", List.of("MIT", "GPL-2.0", "ISC"), true),
                    Arguments.of("(MIT OR Apache-2.0) AND (ISC OR GPL-2.0)", List.of("Apache-2.0", "ISC"), true),
                    Arguments.of("(MIT OR Apache-2.0) AND (GPL-3.0 OR BSD-3-Clause)", List.of("MIT", "BSD-3-Clause"), true),
                    Arguments.of("MIT", List.of("GPL-2.0", "MIT", "MIT", "ISC"), true),
                    Arguments.of("MIT AND ICU", List.of("MIT", "GPL-2.0", "ISC", "Apache-2.0", "ICU"), true),
                    Arguments.of("LicenseRef-X-BSD-3-Clause-Golang", List.of("MIT", "Apache-2.0", "LicenseRef-X-BSD-3-Clause-Golang"), true),
                    Arguments.of("MIT AND LicenseRef-X-BSD-3-Clause-Golang", List.of("MIT", "Apache-2.0", "LicenseRef-X-BSD-3-Clause-Golang"), true),
                    Arguments.of("MIT AND Apache-2.0", List.of("MIT", "Apache-2.0", "LicenseRef-X-BSD-3-Clause-Golang"), true),
                    Arguments.of("MIT", List.of("Apache-2.0"), false),
                    Arguments.of("MIT OR GPL-3.0", List.of("Apache-2.0"), false),
                    Arguments.of("GPL-2.0", List.of("MIT", "Apache-2.0"), false),
                    Arguments.of("MIT OR Apache-2.0", List.of("GPL-2.0"), false),
                    Arguments.of("MIT AND Apache-2.0", List.of("MIT"), false),
                    Arguments.of("MIT AND BSD-3-Clause", List.of("MIT"), false),
                    Arguments.of("GPL-2.0 WITH Classpath-exception-2.0", List.of("GPL-2.0"), false),
                    Arguments.of("GPL-2.0+", List.of("MIT"), false),
                    Arguments.of("(MIT AND GPL-2.0)", List.of("ISC", "GPL-2.0"), false),
                    Arguments.of("MIT AND (GPL-2.0 OR ISC)", List.of("MIT"), false),
                    Arguments.of("(MIT OR Apache-2.0) AND (ISC OR GPL-2.0)", List.of("MIT"), false),
                    Arguments.of("(MIT OR Apache-2.0) AND (GPL-3.0 OR BSD-3-Clause)", List.of("MIT"), false),
                    Arguments.of("MIT AND LicenseRef-X-BSD-3-Clause-Golang", List.of("MIT", "Apache-2.0"), false),
                    Arguments.of("(MIT", List.of("MIT"), false),
                    Arguments.of("GPL-3.0-only", List.of("GPL-2.0-or-later"), true),
                    Arguments.of("GPL-2.0-only", List.of("GPL-2.0-or-later"), true),
                    Arguments.of("GPL-1.0-only", List.of("GPL-2.0-or-later"), false),
                    Arguments.of("GPL-2.0", List.of("GPL-2.0-only"), true),
                    Arguments.of("GPL-2.0-only", List.of("GPL-2.0"), true),
                    Arguments.of("LGPL-3.0", List.of("LGPL-2.0-or-later"), true),
                    Arguments.of("GPL-2.0-with-classpath-exception", List.of("GPL-2.0-only WITH Classpath-exception-2.0"), true),
                    Arguments.of("GPL-2.0-with-classpath-exception", List.of("GPL-2.0 WITH Classpath-exception-2.0"), true),
                    Arguments.of("Apache-1.0+", List.of("Apache-2.0"), true),
                    Arguments.of("GPL-2.0", List.of("GPL-2.0+"), true),
                    Arguments.of("GPL-2.0", List.of("GPL-2.0-or-later"), true),
                    Arguments.of("GPL-3.0", List.of("GPL-2.0+"), true),
                    Arguments.of("GPL-1.0-or-later", List.of("GPL-2.0-or-later"), true),
                    Arguments.of("GPL-1.0+", List.of("GPL-2.0+"), true),
                    Arguments.of("GPL-2.0-only", List.of("GPL-2.0-only"), true),
                    Arguments.of("GPL-2.0", List.of("GPL-2.0-only"), true),
                    Arguments.of("GPL-3.0-only", List.of("GPL-2.0+"), true),
                    Arguments.of("GPL-3.0 WITH Bison-exception-2.2", List.of("GPL-2.0+ WITH Bison-exception-2.2"), true),
                    Arguments.of("Apache-2.0", List.of("Apache-2.0-or-later"), true),
                    Arguments.of("GPL-1.0", List.of("GPL-2.0+"), false),
                    Arguments.of("Apache-1.0", List.of("Apache-2.0+"), false),
                    Arguments.of("Apache-1.0", List.of("Apache-2.0-or-later"), false),
                    Arguments.of("Apache-1.0", List.of("Apache-2.0-only"), false));
        }

        @ParameterizedTest
        @MethodSource("shouldEvaluateArgs")
        void shouldEvaluate(String expression, List<String> allowedIds, boolean expected) {
            assertThat(SpdxExpressions.allows(expression, allowedIds)).isEqualTo(expected);
        }

    }

    @Nested
    class RequiresAnyTest {

        private static Stream<Arguments> shouldEvaluateArgs() {
            return Stream.of(
                    Arguments.of("MIT", List.of("MIT"), true),
                    Arguments.of("MIT", List.of("mit"), true),
                    Arguments.of("MIT AND BSD-3-Clause", List.of("MIT"), true),
                    Arguments.of("GPL-2.0 WITH Classpath-exception-2.0", List.of("GPL-2.0 WITH Classpath-exception-2.0"), true),
                    Arguments.of("GPL-2.0 WITH Classpath-exception-2.0", List.of("GPL-2.0"), false),
                    Arguments.of("GPL-2.0-only", List.of("GPL-2.0"), true),
                    Arguments.of("GPL-2.0+", List.of("GPL-2.0"), true),
                    Arguments.of("MIT AND BSD-3-Clause", List.of("MIT", "GPL-3.0"), true),
                    Arguments.of("MIT OR BSD-3-Clause", List.of("MIT", "BSD-3-Clause"), true),
                    Arguments.of("(MIT AND Apache-2.0) OR (MIT AND GPL-3.0)", List.of("MIT"), true),
                    Arguments.of("GPL-2.0+", List.of("GPL-3.0"), false),
                    Arguments.of("GPL-2.0 WITH Classpath-exception-2.0", List.of("GPL-2.0-only WITH Classpath-exception-2.0"), true),
                    Arguments.of("GPL-2.0+ OR MIT", List.of("GPL-3.0"), false),
                    Arguments.of("MIT OR GPL-3.0", List.of("MIT"), false),
                    Arguments.of("MIT OR GPL-3.0", List.of("MIT", "Apache-2.0"), false),
                    Arguments.of("(MIT", List.of("MIT"), false)
            );
        }

        @ParameterizedTest
        @MethodSource("shouldEvaluateArgs")
        void shouldEvaluate(String expression, List<String> ids, boolean expected) {
            assertThat(SpdxExpressions.requiresAny(expression, ids)).isEqualTo(expected);
        }

    }

}
