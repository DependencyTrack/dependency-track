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
package org.dependencytrack.util;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.util.Arrays;
import java.util.List;

@RunWith(JUnitParamsRunner.class)
public class ComponentVersionTest {

    // versions to test, highest always comes first!
    private Object[] paremetersVersions() {
        return new Object[] {
            new String[] { "2", "1" },
            new String[] { "1", "1-snapshot" },
            new String[] { "1_Final", "1" },
            new String[] { "1.1_Final", "1.1" },
            new String[] { "2-snapshot", "v1-snapshot" },
            new String[] { "1.1-snapshot", "v1-snapshot" },
            new String[] { "01.01-snapshot", "v1-snapshot" },
            new String[] { "1", "1-next.1" }, // one might think next comes later, but only when denoted with ^ sign
            new String[] { "1^next", "1-next.1" },
            new String[] { "1.next", "1" },
            new String[] { "1f.2g.3h.4i.5j.Release", "1a.2b.3c.4d.5e.Final" },
            // new String[] { "1.0", "1" }, 1.0 and 1 are considered equal
            new String[] { "2.0.1.Final-next", "v2.0.1.Final-snapshot" },
            new String[] { "2.33-canary", "v2.33-snapshot" },
            new String[] { "3.0-snapshot", "v2.1.Release-snapshot" },
            new String[] { "3-snapshot", "v1.1-snapshot" },
            new String[] { "3-snapshot", "v01.01-snapshot" },
            new String[] { "v1", "1-alpha.1" },
            new String[] { "v2", "1-next.1" },
            new String[] { "2", "2-a" },
            new String[] { "2a", "2-a" },
            new String[] { "1.2a", "1.2" },
            new String[] { "1.2.1", "1.2a.2" },
            new String[] { "200180416", "200180413" },
            new String[] { "200180416.1", "200180413.2" },
            new String[] { "200180416", "200180416-beta" },
            new String[] { "200180416.alpha", "200180416" }, // alpha is used as postrelease version here
            // ~ operator: sort earlier
            new String[] { "0.5.0", "0.5.0~earlier" },
            new String[] { "0.5.0.earlier", "0.5.0~earlier" },
            new String[] { "0.5.0-earlier", "0.5.0~earlier" },
            new String[] { "0.5.0~earlier2", "0.5.0~earlier1" },
            new String[] { "1", "1-earlier" },
            // ^ operator: sort later
            new String[] { "0.5.0^later", "0.5.0" },
            new String[] { "0.5.0^later", "0.5.0-later" },
            new String[] { "0.5.0^later2", "0.5.0^later1" },
            // sort later
            new String[] { "1.later", "1" },
        };
    }

    @Test
    @Parameters(method = "paremetersVersions")
    public void testCompareVersions(String version1, String version2) {
        Assert.assertTrue("not " + version1 + " > " + version2, ComponentVersion.compareVersions(version1, version2) > 0);
        Assert.assertTrue("not " + version2 + " < " + version1, ComponentVersion.compareVersions(version2, version1) < 0);
    }

    @Test
    @Parameters(method = "paremetersVersions")
    public void testCompareVersionsEquals(String version1, String version2) {
        Assert.assertEquals("1.0 == 1", 0, ComponentVersion.compareVersions("1.0", "1"));
        Assert.assertEquals("1.0.0 == 1", 0, ComponentVersion.compareVersions("1.0.0", "1"));
        Assert.assertEquals("1.0.0 == 1.0", 0, ComponentVersion.compareVersions("1.0.0", "1.0"));
        Assert.assertEquals("1.0.0.0 == 1.0.0", 0, ComponentVersion.compareVersions("1.0.0.0", "1.0.0"));
        Assert.assertEquals("1+mnu1 == 1+mnu2", 0, ComponentVersion.compareVersions("1+mnu1", "1+mnu2"));
        Assert.assertEquals("1+git20221212 == 1+git20101212", 0, ComponentVersion.compareVersions("1+git20221212", "1+git20101212"));
        Assert.assertEquals(version1, 0, ComponentVersion.compareVersions(version1, version1));
        Assert.assertEquals(version2, 0, ComponentVersion.compareVersions(version2, version2));
    }

    @Test
    public void testCompareVersionsNull() {
        Assert.assertEquals(0, ComponentVersion.compareVersions(null, null));
        Assert.assertEquals(0, ComponentVersion.compareVersions("", ""));
        Assert.assertEquals(0, ComponentVersion.compareVersions(null, ""));
        Assert.assertEquals(0, ComponentVersion.compareVersions("", null));
        Assert.assertTrue(ComponentVersion.compareVersions("1", null) > 0);
        Assert.assertTrue(ComponentVersion.compareVersions(null, "1") < 0);
        Assert.assertTrue(ComponentVersion.compareVersions("1", "") > 0);
        Assert.assertTrue(ComponentVersion.compareVersions("", "1") < 0);
    }

    private Object[] paremetersUbuntuVersions() {

        return new Object[] {
            new String[] { "2.0.1f", "2.0.1e" },
            new String[] { "2.0.1f", "1.1.1fubuntu2.4" },
            new String[] { "2.0.1fubuntu2.4", "2.0.1f" },
            new String[] { "2.0.1fubuntu5", "2.0.1fubuntu2.4ppa1" },
            new String[] { "2.0.1fubuntu5ppa1", "2.0.1fubuntu2.4ppa1" },
            new String[] { "2.0.1fubuntu2.4ppa2", "2.0.1fubuntu2.4ppa1" },
            new String[] { "2.0.1f-1", "1.1.1f-1ppa4" },
            new String[] { "2.0.1f-1ubuntu2.4", "1.1.1f-1ubuntu2.4" },
            new String[] { "1.1.1f-1ubuntu2.5", "1.1.1f-1ubuntu2.4" },
            new String[] { "1.1.1g-1ubuntu2.4", "1.1.1f-1ubuntu2.4" },
            new String[] { "4.9.1+nmu1ubuntu2", "4.9.0ubuntu2" },

            // Ubuntu package myapp_1.0-1 < PPA package myapp_1.0-1ppa1
            new String[] { "1.0-1ppa1", "1.0-1" },
            // Ubuntu package myapp_1.0-1ubuntu3 < PPA package myapp_1.0-1ubuntu3ppa1
            new String[] { "1.0-1ubuntu3ppa1", "1.0-1ubuntu3" },
            new String[] { "1.0ppa2", "1.0ppa1" },
            // Test epoch
            new String[] { "2:v1", "1:v1" },
            new String[] { "2:v1", "1:v2" },
            new String[] { "2:v2", "1:v1" },
            new String[] { "2:v2", "1:v2" },
            new String[] { "3:v1", "2:v1" },
            new String[] { "3:v1", "2:v2" },
            new String[] { "3:v2", "2:v2" },
            new String[] { "3:v2", "2:v1" },
            new String[] { "1:9.11.3+dfsg-1ubuntu1.18", "9.11.3+dfsg-1ubuntu1.18" },
            new String[] { "0.97-2build1", "0.97-1build10" },
            new String[] { "0.12.2-1.3ubuntu0.3", "0.12.1-1.3ubuntu0.3" },
            new String[] { "1.56.1", "1.56.1-1" },
            new String[] { "2.56.4-0ubuntu1.18.04.9", "2.56.4-0ubuntu0.18.04.9" },
            new String[] { "2:6.1.2+dfsg-2ubuntu0.1", "2:6.1.2+dfsg1-2ubuntu0.1" },
            new String[] { "3.5.18ubuntu1.6", "3.5.18-1ubuntu1.6" },
        };
    }

    private Object[] parametersDebianVersions() {

        return new Object[] {
            new String[] { "0.17-2", "0.17-1" },
            new String[] { "0.18-0", "0.17-1" },
            new String[] { "1.17-1", "0.17-1" },
            new String[] { "2.1.6+deb1+cvs20081104-13.2", "2.1.5-13.2" },
            new String[] { "2.1.5+deb2+cvs20081104-13.2", "2.1.5+deb1+cvs20081104-13.2" },
            new String[] { "2.1.6+deb1+cvs20081204-13.2", "2.1.5+deb1+cvs20081104-13.2" },
            new String[] { "5.6.0+git+20171128-2", "4.6.0+git+20171128-2" },
            new String[] { "0.100.0-b21", "0.100.0-21" },
            new String[] { "1:007-4build2", "1:007-4build1" },
            new String[] { "1:1.0.10b", "1:1.0.10" },
            new String[] { "1:1.0.10b-1", "1:1.0.10-1" },
            new String[] { "3.0.11-dfsg-2", "3.0.11-dfsg-1" },
            new String[] { "1:9.11.3+dfsg-1ubuntu2.18", "1:9.11.3+dfsg-1ubuntu1.18" },
            new String[] { "4.9.39+dfsg.03-5", "4.9.39+dfsg.02-5" },
            new String[] { "4.9.1+nmu1", "4.9.0+nmu1" },
            new String[] { "1.1.1o-0+deb11u3", "1.1.1n-0+deb11u3" },
            new String[] { "7.9-2+deb11u1", "7.8-2+deb11u1" },
            new String[] { "1.2.16+ds2-2+deb11u1", "1.2.16+ds1-2+deb11u1" },
            new String[] { "2.1.1d-13.3", "2.1.1d-13.2" },
            new String[] { "2.1.1e-13.2", "2.1.1d-13.2" },
        };

    }

    @Test
    @Parameters(method = "paremetersUbuntuVersions")
    public void testCompareUbuntuVersions(String version1, String version2) {
        Assert.assertTrue("not " + version1 + " > " + version2, ComponentVersion.compareVersions(version1, version2) > 0);
        Assert.assertTrue("not " + version2 + " < " + version1, ComponentVersion.compareVersions(version2, version1) < 0);
    }

    @Test
    @Parameters(method = "parametersDebianVersions")
    public void testCompareDebianVersions(String version1, String version2) {
        Assert.assertTrue("not " + version1 + " > " + version2, ComponentVersion.compareVersions(version1, version2) > 0);
        Assert.assertTrue("not " + version2 + " < " + version1, ComponentVersion.compareVersions(version2, version1) < 0);
    }

    @Test
    @Parameters(method = "paremetersUbuntuVersions")
    public void testCompareUbuntuVersionsEquals(String version1, String version2) {
        Assert.assertEquals(version1, 0, ComponentVersion.compareVersions(version1, version1));
        Assert.assertEquals(version2, 0, ComponentVersion.compareVersions(version2, version2));
    }

    @Test
    @Parameters(method = "parametersDebianVersions")
    public void testCompareDebianVersionsEquals(String version1, String version2) {
        Assert.assertEquals(version1, 0, ComponentVersion.compareVersions(version1, version1));
        Assert.assertEquals(version2, 0, ComponentVersion.compareVersions(version2, version2));
    }

    @Test
    public void testCompareDebianVersionsBuilddata() {
        Assert.assertEquals( 0, ComponentVersion.compareVersions("2.1.5+deb1+cvs20081104-14.2", "2.1.5+deb1+cvs20081104-13.2"));
        Assert.assertEquals( 0, ComponentVersion.compareVersions("2.1.5+deb1+cvs20081104-13.3", "2.1.5+deb1+cvs20081104-13.2"));
        Assert.assertEquals( 0, ComponentVersion.compareVersions("2.1.5+deb1+1", "2.1.5+deb1+2"));
    }

    @Test
    public void testHighestVersionNull() {
        Assert.assertNull(ComponentVersion.highestVersion(null, null));
    }

    @Parameters (method = "paremetersVersions")
    public void testHighestVersion(String version1, String version2) {
        Assert.assertEquals(version1, ComponentVersion.highestVersion(version1, version2));
    }

    @Parameters (method = "paremetersUbuntuVersions")
    public void testHighestVersionUbuntu(String version1, String version2) {
        Assert.assertEquals(version1, ComponentVersion.highestVersion(version1, version2));
    }

    @Parameters (method = "parametersDebianVersions")
    public void testHighestVersionDebian(String version1, String version2) {
        Assert.assertEquals(version1, ComponentVersion.highestVersion(version1, version2));
    }

    private Object[] paremetersSemVerVersions() {
        return new Object[] {
            // Stable:
            new String[] { "1.0.0" },
            new String[] { "9.3.0-Final" },
            new String[] { "4.22.0+4e01e86b5fc27661dd585946578d0625dd4af38d" },
            new String[] { "1.0.1-0+20130313144700" },
            new String[] { "4.22.0-b.e.t.a.1+4e01e86.b5fc27-.-661dd5.85946.578d0--625dd4af38d.1a-as1w2" },
            // Unstable:
            new String[] { "1.11.0-1.1" },
            new String[] { "1.2.0-4" },
            new String[] { "2.1.2-2.1" },
            new String[] { "2.2.12-1.1" },
            new String[] { "1.22.333-rc1" },
            new String[] { "9.3.0-BETA.14-77e850b" },
            new String[] { "3.10.0-canary.1" },
            new String[] { "31.0.0-next.1" },
            new String[] { "4.22.0-next.1627591352.4e01e86b5fc27661dd585946578d0625dd4af38d" },
            // 9. A pre-release version MAY be denoted by appending a hyphen and a series of dot separated
            // identifiers immediately following the patch version. Identifiers MUST comprise only ASCII
            // alphanumerics and hyphens [0-9A-Za-z-]. Identifiers MUST NOT be empty. Numeric identifiers
            // MUST NOT include leading zeroes. Pre-release versions have a lower precedence than the
            // associated normal version. A pre-release version indicates that the version is unstable
            // and might not satisfy the intended compatibility requirements as denoted by its associated
            // normal version. Examples: 1.0.0-alpha, 1.0.0-alpha.1, 1.0.0-0.3.7, 1.0.0-x.7.z.92, 1.0.0-x-y-z.--.
            // (semver.org)
            new String[] { "1.10.0-alpha" },
            new String[] { "1.0.10-alpha.1" },
            new String[] { "1.0.0-0.3.7" },
            new String[] { "1.0.0-x.7.z.92" },
            new String[] { "1.0.0-x-y-z.--" },
            // 10. Build metadata MAY be denoted by appending a plus sign and a series of dot separated
            // identifiers immediately following the patch or pre-release version. Identifiers MUST
            // comprise only ASCII alphanumerics and hyphens [0-9A-Za-z-]. Identifiers MUST NOT be empty.
            // Build metadata MUST be ignored when determining version precedence. Thus two versions that
            // differ only in the build metadata, have the same precedence. Examples: 1.0.0-alpha+001,
            // 1.0.0+20130313144700, 1.0.0-beta+exp.sha.5114f85, 1.0.0+21AF26D3----117B344092BD.
            // (semver.org)
            new String[] { "4.22.0-beta+4e01e86b5fc27661dd585946578d0625dd4af38d-final" },
            new String[] { "11.1.0-alpha+001" },
            new String[] { "1.0.0-beta+exp.sha.5114f85" },
            new String[] { "0.2.2-beta2+git20190406.ef77f01" },

            new String[] { "2.5.1-develop-0017" },
            new String[] { "1.0.0-1.develop09" },
            new String[] { "1.0.0-feat-name09" },
            new String[] { "2.5.1-develop-0017" },
            new String[] { "0.0.4" },
            new String[] { "1.2.3" },
            new String[] { "10.20.30" },
            new String[] { "1.1.2-prerelease+meta" },
            new String[] { "1.1.2+meta" },
            new String[] { "1.1.2+meta-valid" },
            new String[] { "1.0.0-alpha" },
            new String[] { "1.0.0-beta" },
            new String[] { "1.0.0-alpha.beta" },
            new String[] { "1.0.0-alpha.beta.1" },
            new String[] { "1.0.0-alpha.1" },
            new String[] { "1.0.0-alpha0.valid" },
            new String[] { "1.0.0-alpha.0valid" },
            new String[] { "1.0.0-alpha-a.b-c-somethinglong+build.1-aef.1-its-okay" },
            new String[] { "1.0.0-rc.1+build.1" },
            new String[] { "2.0.0-rc.1+build.123" },
            new String[] { "1.2.3-beta" },
            new String[] { "10.2.3-DEV-SNAPSHOT" },
            new String[] { "1.2.3-SNAPSHOT-123" },
            new String[] { "1.0.0" },
            new String[] { "2.0.0" },
            new String[] { "1.1.7" },
            new String[] { "2.0.0+build.1848" },
            new String[] { "2.0.1-alpha.1227" },
            new String[] { "1.0.0-alpha+beta" },
            new String[] { "1.2.3----RC-SNAPSHOT.12.9.1--.12+788" },
            new String[] { "1.2.3----R-S.12.9.1--.12+meta" },
            new String[] { "1.2.3----RC-SNAPSHOT.12.9.1--.12" },
            new String[] { "1.0.0+0.build.1-rc.10000aaa-kk-0.1" },
            new String[] { "99999999999999999999999.999999999999999999.99999999999999999" },
            new String[] { "1.0.0-0A.is.legal" },

        };
    }

    private Object[] paremetersNotSemVerVersions() {
        return new Object[] {
            new String[] { "1.0" },
            new String[] { "1.0.1.0" },
            new String[] { "version1" },
            new String[] { "01" },
            new String[] { "9.3.0.Final" },
            new String[] { "1.0.1.0+20130313144700" },
        };
    }

    @Test
    @Parameters(method = "paremetersSemVerVersions")
    public void testIsSemVer(String version) {
        Assert.assertTrue("not semver: " + version, ComponentVersion.isSemVer(version));
    }

    @Test
    @Parameters(method = "paremetersNotSemVerVersions")
    public void testIsNotSemVerVersion(String version) {
        Assert.assertFalse("is semver: " + version, ComponentVersion.isSemVer(version));
    }

    private Object[] paremetersStableVersions() {
        return new Object[] {
            // Stable:
            new String[] { "2.0.1f" },
            new String[] { "1" },
            new String[] { "1.0" },
            new String[] { "1.0.0" },
            new String[] { "1.0.0" },
            new String[] { "1a" },
            new String[] { "9.3.0.Final" },
            new String[] { "9.3.0.RELEASE" },
            new String[] { "4.22.0+4e01e86b5fc27661dd585946578d0625dd4af38d" },
            // semver doesn't allow leading zero's but it doesn't hurt:
            new String[] { "01.002.0003" },
            new String[] { "1.0.1.0+20130313144700" },
            new String[] { "1.0.0+21AF26D3----117B344092BD" },
            // ubuntu package versions, see https://github.com/DependencyTrack/dependency-track/issues/1374
            new String[] { "1.1.1f-1ubuntu2.4" },
            new String[] { "0.18ubuntu0.18.04.1" },
            new String[] { "0.37ubuntu0.15" },
            new String[] { "2:1.02.145-4.1ubuntu3.18.04.3" },
            new String[] { "2:1.02.145-4.1ubuntu3.18.04.3" },
            new String[] { "3.1-1ubuntu0.1" },
            new String[] { "2018013001" },
            new String[] { "2018013001" },
            // debian
            new String[] { "1.1.1n-0+deb11u3" },
            new String[] { "4.9.39+dfsg.02-5" },
            new String[] { "2.2+git20080214.600fc29+dfsg-2" },
            new String[] { "7.8-2+deb11u1" },
            new String[] { "1.4.0~dfsg+~1.4.5-2" },
            new String[] { "1.2.16+ds1-2+deb11u1" },
            // Semver:
            new String[] { "1.1.2+meta" },
            new String[] { "1.1.2+meta-valid" },
            new String[] { "2.0.0+build.1848" },
            new String[] { "1.0.0+0.build.1-rc.10000aaa-kk-0.1" },
        };
    }

    private Object[] paremetersUnstableVersions() {
        return new Object[] {
            // Unstable:
            new String[] { "1.11.0-1.1" },
            new String[] { "1.2.0-4" },
            new String[] { "2.1.2-2.1" },
            new String[] { "2.2.12-1.1" },
            new String[] { "2.1.1d-13.2" },
            new String[] { "version" },
            new String[] { "1-A" },
            new String[] { "1-alpha" },
            new String[] { "1-b" },
            new String[] { "11.1-SNApshot" },
            new String[] { "1.22.333-rc1" },
            new String[] { "9.3.0-BETA.14-77e850b" },
            new String[] { "3.10.0-canary.1" },
            new String[] { "31.0.0-next.1" },
            // semver doesn't allow leading zero's but it doesn't hurt:
            new String[] { "01.002.0003-snapshot" },
            new String[] { "4.22.0-next.1627591352.4e01e86b5fc27661dd585946578d0625dd4af38d" },
            // 9. A pre-release version MAY be denoted by appending a hyphen and a series of dot separated
            // identifiers immediately following the patch version. Identifiers MUST comprise only ASCII
            // alphanumerics and hyphens [0-9A-Za-z-]. Identifiers MUST NOT be empty. Numeric identifiers
            // MUST NOT include leading zeroes. Pre-release versions have a lower precedence than the
            // associated normal version. A pre-release version indicates that the version is unstable
            // and might not satisfy the intended compatibility requirements as denoted by its associated
            // normal version. Examples: 1.0.0-alpha, 1.0.0-alpha.1, 1.0.0-0.3.7, 1.0.0-x.7.z.92, 1.0.0-x-y-z.--.
            // (semver.org)
            new String[] { "1.10.0-alpha" },
            new String[] { "1.0.10-alpha.1" },
            new String[] { "1.0.0-0.3.7" },
            new String[] { "1.0.0-x.7.z.92" },
            new String[] { "11.10.0-x-y-z.--." },
            // 10. Build metadata MAY be denoted by appending a plus sign and a series of dot separated
            // identifiers immediately following the patch or pre-release version. Identifiers MUST
            // comprise only ASCII alphanumerics and hyphens [0-9A-Za-z-]. Identifiers MUST NOT be empty.
            // Build metadata MUST be ignored when determining version precedence. Thus two versions that
            // differ only in the build metadata, have the same precedence. Examples: 1.0.0-alpha+001,
            // 1.0.0+20130313144700, 1.0.0-beta+exp.sha.5114f85, 1.0.0+21AF26D3----117B344092BD.
            // (semver.org)
            new String[] { "11.1.0-alpha+001" },
            new String[] { "1.0.0-beta+exp.sha.5114f85" },
            new String[] { "0.2.2-beta2+git20190406.ef77f01-3+b1" },
            new String[] { "2.0.1-alpha.1227" },
            new String[] { "1.0.0-alpha+beta" },
            new String[] { "1.2.3----RC-SNAPSHOT.12.9.1--.12+788" },
            new String[] { "1.2.3----R-S.12.9.1--.12+meta" },
            new String[] { "1.2.3----RC-SNAPSHOT.12.9.1--.12" },
            // non-semver
            new String[] { "0.0.0-develop.09" },
            new String[] { "0.0.0-feat-name.09" },
        };
    }

    @Test
    @Parameters(method = "paremetersStableVersions")
    public void testIsStableVersion(String version) {
        Assert.assertTrue("not stable: " + version, ComponentVersion.isStableVersion(version));
    }

    @Test
    @Parameters(method = "paremetersUnstableVersions")
    public void testIsUntableVersion(String version) {
        Assert.assertFalse("not unstable: " + version, ComponentVersion.isStableVersion(version));
    }

    private Object[] highestStableOrUnstableVersionParams() {
        return new Object[] {
            new Object[] { "2", Arrays.asList("1", "2", "2-snapshot") },
            new Object[] { "1", Arrays.asList("1") },
            new Object[] { "2-snapshot", Arrays.asList("1", "2-snapshot") },
            new Object[] { "2", Arrays.asList("1", "2") },
            new Object[] { "2", Arrays.asList("1", "2", "2-alpha") },
            new Object[] { "2", Arrays.asList("1", "2", "2-beta") },
            new Object[] { "2", Arrays.asList("1", "2", "2-rc1") },
            new Object[] { "9.3.0-beta.14-77e850b", Arrays.asList("9.2.3", "9.3.0-beta.14-77e850b") },
            new Object[] { "v1", Arrays.asList("v1") },
            new Object[] { "v2-snapshot", Arrays.asList("1", "v2-snapshot") },
            new Object[] { "2", Arrays.asList("v1", "2") },
            new Object[] { "v2", Arrays.asList("v1", "v2") },
            new Object[] { "v2", Arrays.asList("1", "v2") },
        };
    }

    @Test
    @Parameters(method = "highestStableOrUnstableVersionParams")
    public void testfindHighestStableOrUnstableVersion(String highestVersion, List<String> list) {
        Assert.assertNull(ComponentVersion.findHighestStableOrUnstableVersion(Arrays.asList()));
        Assert.assertEquals(highestVersion, ComponentVersion.findHighestStableOrUnstableVersion(list));
    }

    private Object[] highestStableVersionParams() {
        return new Object[] {
            new Object[] { "1", Arrays.asList("1") },
            new Object[] { "1", Arrays.asList("1", "0.9.9") },
            new Object[] { "1", Arrays.asList("1", "2-snapshot") },
            new Object[] { "1", Arrays.asList("1", "2-rc1") },
            new Object[] { "1", Arrays.asList("1", "2-alpha") },
            new Object[] { "1", Arrays.asList("1", "2-m1") },
            new Object[] { "2.0", Arrays.asList("1.2.3", "2.0") },
            new Object[] { "2", Arrays.asList("1", "2", "2-snapshot") },
            new Object[] { "2", Arrays.asList("1", "2", "2-a") },
            new Object[] { "v2", Arrays.asList("1", "v2", "2-alpha") },
            new Object[] { "2", Arrays.asList("v1", "2", "2-beta") },
            new Object[] { "2", Arrays.asList("v1", "2", "v2-rc1") },
            new Object[] { "9.2.3", Arrays.asList("9.2.3", "9.3.0-beta.14-77e850b") },
        };
    }

    @Test
    @Parameters(method = "highestStableVersionParams")
    public void testfindHighestStableVersion(String highestVersion, List<String> list) {
        Assert.assertNull(ComponentVersion.findHighestStableVersion(Arrays.asList()));
        Assert.assertNull(ComponentVersion.findHighestStableVersion(Arrays.asList("1-a", "2-snapshot", "2-rc1")));
        Assert.assertEquals(highestVersion, ComponentVersion.findHighestStableVersion(list));
    }

    private Object[] highestVersionParams() {
        return new Object[] {
            new Object[] {"1", Arrays.asList("1") },
            new Object[] {"1", Arrays.asList("1", "0.9.9") },
            new Object[] {"1", Arrays.asList("1", "2-snapshot") },
            new Object[] {"2-snapshot", Arrays.asList("1-snapshot", "2-snapshot") },
            new Object[] {"1", Arrays.asList("1", "2-rc1") },
            new Object[] {"1", Arrays.asList("1", "2-alpha") },
            new Object[] {"1", Arrays.asList("1", "2-m1") },
            new Object[] {"2.0", Arrays.asList("1.2.3", "2.0") },
            new Object[] {"2", Arrays.asList("1", "2", "2-snapshot") },
            new Object[] {"2", Arrays.asList("1", "2", "2-a") },
            new Object[] {"2", Arrays.asList("1", "2", "2-alpha") },
            new Object[] {"2", Arrays.asList("1", "2", "2-beta") },
            new Object[] {"2", Arrays.asList("1", "2", "2-rc1") },
            // N.B. 2.rc1 would be a better choise than 2-snapshot :-(
            new Object[] {"2-snapshot", Arrays.asList("1-a", "2-snapshot", "2-rc1") },
        };
    }

    @Test
    @Parameters(method = "highestVersionParams")
    public void testfindHighestVersion(String highestVersion, List<String> list) {
        Assert.assertNull(ComponentVersion.findHighestVersion(Arrays.asList()));
        Assert.assertEquals(highestVersion, ComponentVersion.findHighestVersion(list));
    }

}