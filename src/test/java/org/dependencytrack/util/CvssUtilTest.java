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
package org.dependencytrack.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class CvssUtilTest {
    @Test
    void testParseNull() {
        assertNull(CvssUtil.parse(null));
    }

    @Test
    void testParseValidCvss2WithPrefix() {
        final var result = CvssUtil.parse("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P");
        assertNotNull(result);
        assertEquals("AV:N/AC:L/Au:N/C:P/I:P/A:P", result.toString());
    }

    @Test
    void testParseValidCvss2WithoutPrefix() {
        final var vector = "AV:N/AC:L/Au:N/C:P/I:P/A:P";
        final var result = CvssUtil.parse(vector);
        assertNotNull(result);
        assertEquals(vector, result.toString());
    }

    @Test
    void testParseValidCvss2WithParentheses() {
        final var result = CvssUtil.parse("(AV:N/AC:L/Au:N/C:P/I:P/A:P)");
        assertNotNull(result);
        assertEquals("AV:N/AC:L/Au:N/C:P/I:P/A:P", result.toString());
    }

    @Test
    void testParseValidCvss2WithPrefixAndParentheses() {
        final var result = CvssUtil.parse("CVSS:2.0/(AV:N/AC:L/Au:N/C:P/I:P/A:P)");
        assertNotNull(result);
        assertEquals("AV:N/AC:L/Au:N/C:P/I:P/A:P", result.toString());
    }

    @Test
    void testParseInvalidCvssVector() {
        final var result = CvssUtil.parse("INVALID:VECTOR");
        assertNull(result);
    }

    @Test
    void testParseEmptyString() {
        final var result = CvssUtil.parse("");
        assertNull(result);
    }
}
