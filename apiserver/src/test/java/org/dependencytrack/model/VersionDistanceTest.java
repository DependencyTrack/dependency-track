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

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class VersionDistanceTest {

    @Test
    public void testVersionDistance() {
        assertEquals("0:1.?.?", new VersionDistance("1").toString());
        assertEquals("1:?.?.?", new VersionDistance("1:?").toString());
        assertEquals("0:0.0.0", new VersionDistance().toString());
        assertEquals("0:0.0.0", new VersionDistance(null).toString());
        assertEquals("0:0.0.0", new VersionDistance(0,0,0).toString());
        assertEquals("0:1.?.?", new VersionDistance(1, -1,-1).toString());
        assertEquals("0:0.2.?", new VersionDistance(0, 2, -1).toString());
        assertEquals("0:0.2.?", new VersionDistance("0:0.2").toString());
        assertEquals("0:2.?.?", new VersionDistance("2").toString());

        assertThrows(NumberFormatException.class, () -> new VersionDistance("ax").toString());
        assertThrows(NumberFormatException.class, () -> new VersionDistance("1a").toString());
        assertThrows(NumberFormatException.class, () -> new VersionDistance("1.2.3.4").toString());
        assertThrows(NumberFormatException.class, () -> new VersionDistance("1a.2b.3c").toString());
        assertThrows(IllegalArgumentException.class, () -> new VersionDistance("1.0.0").toString());
        assertThrows(IllegalArgumentException.class, () -> new VersionDistance("1.1.0").toString());
        assertThrows(IllegalArgumentException.class, () -> new VersionDistance("?:1.0.0").toString());
        assertThrows(IllegalArgumentException.class, () -> new VersionDistance("0:?.0.0").toString());
        assertThrows(IllegalArgumentException.class, () -> new VersionDistance("?:1.0.0").toString());
        assertThrows(IllegalArgumentException.class, () -> new VersionDistance("0:?.1.0").toString());
    }

    @Test
    public void testCompareTo() {
        assertEquals(0, new VersionDistance(null).compareTo(new VersionDistance("0")));
        assertTrue(new VersionDistance("2.?.?").compareTo(new VersionDistance("1.?.?")) > 0);

        assertEquals(0, new VersionDistance().compareTo(new VersionDistance()));
        assertEquals(0, new VersionDistance("0.0").compareTo(new VersionDistance("0")));
        assertEquals(0, new VersionDistance("1.?.?").compareTo(new VersionDistance("1.?.?")));

        assertTrue(new VersionDistance("1").compareTo(new VersionDistance()) > 0);
        assertTrue(new VersionDistance("1").compareTo(new VersionDistance(null)) > 0);
        assertTrue(new VersionDistance("1.?").compareTo(new VersionDistance("0")) > 0);
        assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("0.0")) > 0);
        assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("0.0.0")) > 0);
        assertTrue(new VersionDistance("2.?.?").compareTo(new VersionDistance("1.?.?")) > 0);
        assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("0.1.?")) > 0);
        assertTrue(new VersionDistance("0.1.?").compareTo(new VersionDistance("0.0.1")) > 0);

        assertTrue(new VersionDistance().compareTo(new VersionDistance("1")) < 0);
        assertTrue(new VersionDistance(null).compareTo(new VersionDistance("1")) < 0);
        assertTrue(new VersionDistance("0").compareTo(new VersionDistance("1.?")) < 0);
        assertTrue(new VersionDistance("0.0").compareTo(new VersionDistance("0.0.1")) < 0);
        assertTrue(new VersionDistance("0.1.?").compareTo(new VersionDistance("1.?.?")) < 0);
        assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("2.?.?")) < 0);
        assertTrue(new VersionDistance("1.?.?").compareTo(new VersionDistance("2.?.?")) < 0);
        assertTrue(new VersionDistance("0.1.?").compareTo(new VersionDistance("0.2.?")) < 0);
        assertTrue(new VersionDistance("0.0.1").compareTo(new VersionDistance("0.0.2")) < 0);

        assertTrue(VersionDistance.getVersionDistance("1.0.0", "0.1.0").compareTo(new VersionDistance("1.?.?")) == 0);
        assertTrue(VersionDistance.getVersionDistance("1.1.0", "1.0.0").compareTo(new VersionDistance("0.1.?")) == 0);
        assertTrue(VersionDistance.getVersionDistance("1.0.0", "1.1.0").compareTo(new VersionDistance("0.1.?")) == 0);
        assertTrue(VersionDistance.getVersionDistance("1.2.3", "2.1.0").compareTo(new VersionDistance("1.?.?")) == 0);
        assertTrue(VersionDistance.getVersionDistance("2.2.2", "2.4.4").compareTo(new VersionDistance("0.1.?")) > 0);
        assertTrue(VersionDistance.getVersionDistance("1.1.1", "1.1.3").compareTo(new VersionDistance("0.0.1")) > 0);
    }

    @Test
    public void testEquals() {
        assertEquals(new VersionDistance("0.0"), new VersionDistance(""));
        assertEquals(new VersionDistance("0:0"), new VersionDistance(null));
        assertEquals(new VersionDistance("4:?.?.?"), new VersionDistance("4:?"));
        assertEquals(new VersionDistance("1.?.?"), new VersionDistance("1"));
        assertEquals(new VersionDistance("0:1.?.?"), new VersionDistance("1.?"));
    }

    @Test
    public void testGetVersionDistance() {
        assertEquals(new VersionDistance("0.0.0"), VersionDistance.getVersionDistance("", null));
        assertEquals(new VersionDistance("0.0.0"), VersionDistance.getVersionDistance(null, ""));
        assertEquals(new VersionDistance("1.?.?"), VersionDistance.getVersionDistance("2", "1.0"));
        assertEquals(new VersionDistance("0.1.?"), VersionDistance.getVersionDistance("1", "1.1.0"));
        assertEquals(new VersionDistance("0.0.1"), VersionDistance.getVersionDistance("1", "1.0.1"));
        assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("1.2", "3.4.0"));
        assertEquals(new VersionDistance("0:2.?"), VersionDistance.getVersionDistance("1.f", "3.4.0"));
        assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("1.", "3.4.0"));
        assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("1.2.3", "3.4.0"));
        assertEquals(new VersionDistance("3.?.?"), VersionDistance.getVersionDistance("0.1.2", "3.4.0"));
        assertEquals(new VersionDistance("0.2.?"), VersionDistance.getVersionDistance("3.2.2", "3.4.0"));
        assertEquals(new VersionDistance("0.0.1"), VersionDistance.getVersionDistance("0.0.1", "0.0.2"));
        assertEquals(new VersionDistance("2.?.?"), VersionDistance.getVersionDistance("3.4.0", "1.2.3"));
        assertEquals(new VersionDistance("3.?.?"), VersionDistance.getVersionDistance("3.4.0", "0.1.2"));
        assertEquals(new VersionDistance("0.2.?"), VersionDistance.getVersionDistance("3.4.0", "3.2.2"));
        assertEquals(new VersionDistance("0.0.1"), VersionDistance.getVersionDistance("0.0.2", "0.0.1"));
        // optional build numbers are ignored:
        assertEquals(new VersionDistance("0.0.0"), VersionDistance.getVersionDistance("0.0.0.1", "0.0.0.5"));

        assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("a:", "1"));
        assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("1a.2.3", "1"));
        assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("1.2a.3", "1"));
        assertThrows(NumberFormatException.class, () -> VersionDistance.getVersionDistance("1.2.3a", "1"));
    }

    @Test
    public void testParse() {
        assertEquals(Arrays.asList(new VersionDistance(0,1,-1)), VersionDistance.parse("0.1.?"));
        assertEquals(Arrays.asList(new VersionDistance(1,-1,-1), new VersionDistance(0,1,-1)), VersionDistance.parse("1.1.?"));
        assertEquals(Arrays.asList(new VersionDistance(1, -1,-1,-1), new VersionDistance(1,-1, -1), new VersionDistance(0,1,-1)), VersionDistance.parse("1:1.1.?"));
        assertEquals(Arrays.asList(), VersionDistance.parse("0:?.?.?"));

        assertThrows(IllegalArgumentException.class, () -> VersionDistance.parse("1.2.3a.1"));
    }

}