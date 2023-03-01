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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.repositories;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

public class AbstractMetaAnalyzerTest {

    @Test
    public void testCompareVersions() {
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions(null, null));
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions(null, "1"));
        Assert.assertEquals(1, AbstractMetaAnalyzer.compareVersions("1", null));
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions("1-snapshot", "1"));
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions("v1-snapshot", "2-snapshot"));
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions("v1-snapshot", "1.1-snapshot"));
        Assert.assertEquals(-1, AbstractMetaAnalyzer.compareVersions("v1-snapshot", "01.01-snapshot"));
        Assert.assertEquals(-2, AbstractMetaAnalyzer.compareVersions("1", "1-next.1"));
        Assert.assertEquals(3, AbstractMetaAnalyzer.compareVersions("2.0.1.Final-next", "v2.0.1.Final-snapshot"));
        Assert.assertEquals(3, AbstractMetaAnalyzer.compareVersions("2.33-canary", "v2.33-snapshot"));
        Assert.assertEquals(1, AbstractMetaAnalyzer.compareVersions("3.0-snapshot", "v2.1.Release-snapshot"));
        Assert.assertEquals(1, AbstractMetaAnalyzer.compareVersions("3-snapshot", "v1.1-snapshot"));
        Assert.assertEquals(1, AbstractMetaAnalyzer.compareVersions("3-snapshot", "v01.01-snapshot"));
        Assert.assertEquals(5, AbstractMetaAnalyzer.compareVersions("v1", "1-alpha.1"));
        Assert.assertEquals(1, AbstractMetaAnalyzer.compareVersions("v2", "1-next.1"));
    }

    @Test
    public void testHighestVersion() {
        Assert.assertNull(AbstractMetaAnalyzer.highestVersion(null, null));
        Assert.assertEquals("0.0.1", AbstractMetaAnalyzer.highestVersion("0.0.1", null));
        Assert.assertEquals("0.0.1", AbstractMetaAnalyzer.highestVersion(null, "0.0.1"));
        Assert.assertEquals("2", AbstractMetaAnalyzer.highestVersion("2-SNAPSHOT", "2"));
        Assert.assertEquals("2", AbstractMetaAnalyzer.highestVersion("2-RC1", "2"));
        Assert.assertEquals("2", AbstractMetaAnalyzer.highestVersion("2-alpha", "2"));
        Assert.assertEquals("2.0.0", AbstractMetaAnalyzer.highestVersion("1.9.9.9", "2.0.0"));
        Assert.assertEquals("2", AbstractMetaAnalyzer.highestVersion("1.9", "2"));
        Assert.assertEquals("0.1", AbstractMetaAnalyzer.highestVersion("0.1", "0.0.1"));
        // N.B. we would like to see 2 being higher as 2-a, but since we're only interested in stable versions it doesn't maater
        Assert.assertEquals("2-a", AbstractMetaAnalyzer.highestVersion("2-a", "2"));
        Assert.assertEquals("2", AbstractMetaAnalyzer.highestVersion("v2", "2"));
        Assert.assertEquals("v2.2", AbstractMetaAnalyzer.highestVersion("v2.1", "v2.2"));
        Assert.assertEquals("v2.2", AbstractMetaAnalyzer.highestVersion("v2.2", "v2.1"));
        Assert.assertEquals("v2", AbstractMetaAnalyzer.highestVersion("1", "v2"));
        Assert.assertEquals("v2", AbstractMetaAnalyzer.highestVersion("v1-rc1", "v2"));
        Assert.assertEquals("v2", AbstractMetaAnalyzer.highestVersion("v2-alpha", "v2"));
        Assert.assertEquals("v2", AbstractMetaAnalyzer.highestVersion("v2-snapshot", "v2"));
        Assert.assertEquals("v2-snapshot", AbstractMetaAnalyzer.highestVersion("v1", "v2-snapshot"));
        Assert.assertEquals("9.3.0-beta.14-77e850b", AbstractMetaAnalyzer.highestVersion("9.2.3", "9.3.0-beta.14-77e850b"));
    }

    @Test
    public void testIsStableVersion() {
        // Stable:
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("version"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("1"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("1.0"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("1.0.0"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("1.0.0"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("1a"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("9.3.0.Final"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("9.3.0.RELEASE"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("4.22.0+4e01e86b5fc27661dd585946578d0625dd4af38d"));
        // semver doesn't allow leading zero's but it doesn't hurt:
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("01.002.0003"));
        // Unstable:
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("1-A"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("1-alpha"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("1-b"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("11.1-SNApshot"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("11.1-develop"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("11.1-dev"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("1.22.333-rc1"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("9.3.0-BETA.14-77e850b"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("3.10.0-canary.1"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("31.0.0-next.1"));
        // semver doesn't allow leading zero's but it doesn't hurt:
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("01.002.0003-snapshot"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("4.22.0-next.1627591352.4e01e86b5fc27661dd585946578d0625dd4af38d"));
        // 9. A pre-release version MAY be denoted by appending a hyphen and a series of dot separated
        // identifiers immediately following the patch version. Identifiers MUST comprise only ASCII
        // alphanumerics and hyphens [0-9A-Za-z-]. Identifiers MUST NOT be empty. Numeric identifiers
        // MUST NOT include leading zeroes. Pre-release versions have a lower precedence than the
        // associated normal version. A pre-release version indicates that the version is unstable
        // and might not satisfy the intended compatibility requirements as denoted by its associated
        // normal version. Examples: 1.0.0-alpha, 1.0.0-alpha.1, 1.0.0-0.3.7, 1.0.0-x.7.z.92, 1.0.0-x-y-z.--.
        // (semver.org)
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("1.10.0-alpha"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("1.0.10-alpha.1"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("1.0.0-0.3.7"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("1.0.0-x.7.z.92"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("11.10.0-x-y-z.--."));
        // 10. Build metadata MAY be denoted by appending a plus sign and a series of dot separated
        // identifiers immediately following the patch or pre-release version. Identifiers MUST
        // comprise only ASCII alphanumerics and hyphens [0-9A-Za-z-]. Identifiers MUST NOT be empty.
        // Build metadata MUST be ignored when determining version precedence. Thus two versions that
        // differ only in the build metadata, have the same precedence. Examples: 1.0.0-alpha+001,
        // 1.0.0+20130313144700, 1.0.0-beta+exp.sha.5114f85, 1.0.0+21AF26D3----117B344092BD.
        // (semver.org)
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("11.1.0-alpha+001"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("1.0\1.0+20130313144700"));
        Assert.assertFalse(AbstractMetaAnalyzer.isStableVersion("1.0.0-beta+exp.sha.5114f85"));
        Assert.assertTrue(AbstractMetaAnalyzer.isStableVersion("1.0.0+21AF26D3----117B344092BD"));
    }

    @Test
    public void testfindHighestStableOrUnstableVersion() {
        Assert.assertNull(AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList()));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("1")));
        Assert.assertEquals("2-snapshot", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("1", "2-snapshot")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("1", "2")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("1", "2", "2-snapshot")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("1", "2", "2-alpha")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("1", "2", "2-beta")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("1", "2", "2-rc1")));
        Assert.assertEquals("9.3.0-beta.14-77e850b", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("9.2.3", "9.3.0-beta.14-77e850b")));
        Assert.assertEquals("v1", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("v1")));
        Assert.assertEquals("v2-snapshot", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("1", "v2-snapshot")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("v1", "2")));
        Assert.assertEquals("v2", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("v1", "v2")));
        Assert.assertEquals("v2", AbstractMetaAnalyzer.findHighestStableOrUnstableVersion(Arrays.asList("1", "v2")));

    }

    @Test
    public void testfindHighestStableVersion() {
        Assert.assertNull(AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList()));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1", "0.9.9")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1", "2-snapshot")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1", "2-rc1")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1", "2-alpha")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1", "2-m1")));
        Assert.assertEquals("2.0", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1.2.3", "2.0")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1", "2", "2-snapshot")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1", "2", "2-a")));
        Assert.assertEquals("v2", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1", "v2", "2-alpha")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("v1", "2", "2-beta")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("v1", "2", "v2-rc1")));
        Assert.assertNull(AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("1-a", "2-snapshot", "2-rc1")));
        Assert.assertEquals("9.2.3", AbstractMetaAnalyzer.findHighestStableVersion(Arrays.asList("9.2.3", "9.3.0-beta.14-77e850b")));
    }

    @Test
    public void testfindHighestVersion() {
        Assert.assertNull(AbstractMetaAnalyzer.findHighestVersion(Arrays.asList()));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "0.9.9")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "2-snapshot")));
        Assert.assertEquals("2-snapshot", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1-snapshot", "2-snapshot")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "2-rc1")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "2-alpha")));
        Assert.assertEquals("1", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "2-m1")));
        Assert.assertEquals("2.0", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1.2.3", "2.0")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "2", "2-snapshot")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "2", "2-a")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "2", "2-alpha")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "2", "2-beta")));
        Assert.assertEquals("2", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1", "2", "2-rc1")));
        // N.B. 2.rc1 would be a better choise than 2-snapshot :-(
        Assert.assertEquals("2-snapshot", AbstractMetaAnalyzer.findHighestVersion(Arrays.asList("1-a", "2-snapshot", "2-rc1")));
    }

}
