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
package org.dependencytrack.policy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class MatcherTest {

    @Test
    void checkNulls() {
        Assertions.assertTrue(Matcher.matches(null, null));
        Assertions.assertFalse(Matcher.matches("", null));
        Assertions.assertFalse(Matcher.matches(null, ""));
    }

    @Test
    void checkExact() {
        Assertions.assertTrue(Matcher.matches("", ""));
        Assertions.assertTrue(Matcher.matches("something", "something"));
    }

    @Test
    void checkPartials() {
        Assertions.assertTrue(Matcher.matches("something", "some"));
        Assertions.assertTrue(Matcher.matches("something", "meth"));
        Assertions.assertTrue(Matcher.matches("something", "thing"));
    }

    @Test
    void checkWildcards() {
        Assertions.assertTrue(Matcher.matches("something", "some*"));
        Assertions.assertTrue(Matcher.matches("something", "*thing"));
    }

    @Test
    void checkRegex() {
        Assertions.assertTrue(Matcher.matches("something", "^some.*"));
        Assertions.assertTrue(Matcher.matches("something", ".*thing$"));
    }
}
