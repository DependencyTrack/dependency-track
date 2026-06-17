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
package org.dependencytrack.support.distrometadata;

import com.github.packageurl.PackageURL;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class DebianDistributionTest {

    @Nested
    class FromPurlTest {

        @ParameterizedTest
        @CsvSource(value = {
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?arch=amd64&distro=debian-11.6, debian-11",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=debian-11, debian-11",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=debian-7, debian-7",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=bullseye, debian-11",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=debian-bullseye, debian-11",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=debian-sid, debian-sid",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=sid, debian-sid",
        })
        void shouldParse(String purl, String expectedQualifier) throws Exception {
            final OsDistribution distro = OsDistribution.of(new PackageURL(purl));
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(DebianDistribution.class);
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
        }

    }

    @Nested
    class KnownReleasesTest {

        @ParameterizedTest
        @CsvSource(value = {
                "1.1, buzz",
                "1.2, rex",
                "1.3, bo",
                "2.0, hamm",
                "2.1, slink",
                "2.2, potato",
                "3.0, woody",
                "3.1, sarge",
                "4.0, etch",
                "5.0, lenny",
                "6.0, squeeze",
                "7, wheezy",
                "8, jessie",
                "9, stretch",
                "10, buster",
                "11, bullseye",
                "12, bookworm",
                "13, trixie",
                "14, forky",
        })
        void shouldResolveFromVersion(String version, String expectedSeries) {
            final DebianDistribution distro = DebianDistribution.of(version);
            assertThat(distro).isNotNull();
            assertThat(distro.series()).isEqualTo(expectedSeries);
            assertThat(distro.version()).isEqualTo(version);
        }

        @Test
        void shouldHandleSidWithNoVersion() {
            final DebianDistribution distro = DebianDistribution.of("sid");
            assertThat(distro).isNotNull();
            assertThat(distro.series()).isEqualTo("sid");
            assertThat(distro.version()).isNull();
            assertThat(distro.purlQualifierValue()).isEqualTo("debian-sid");
        }

    }

    @Nested
    class MatchesTest {

        @ParameterizedTest
        @CsvSource(value = {
                "7, pkg:deb/debian/apt?distro=debian-7, true",
                "7, pkg:deb/debian/apt?distro=debian-7.11, true",
                "7, pkg:deb/debian/apt?distro=wheezy, true",
                "7, pkg:deb/debian/apt?distro=debian-wheezy, true",
                "11, pkg:deb/debian/apt?distro=debian-11, true",
                "11, pkg:deb/debian/apt?distro=debian-11.6, true",
                "11, pkg:deb/debian/apt?distro=bullseye, true",
                "bullseye, pkg:deb/debian/apt?distro=debian-11, true",
                "sid, pkg:deb/debian/apt?distro=debian-sid, true",
                "sid, pkg:deb/debian/apt?distro=sid, true",
                "7, pkg:deb/debian/apt?distro=debian-11, false",
                "11, pkg:deb/debian/apt?distro=debian-7, false",
                "wheezy, pkg:deb/debian/apt?distro=debian-bullseye, false",
                "sid, pkg:deb/debian/apt?distro=debian-11, false",
        })
        void shouldMatch(String versionOrSeries, String purl, boolean shouldMatch) throws Exception {
            final DebianDistribution distroA = DebianDistribution.of(versionOrSeries);
            assertThat(distroA).isNotNull();

            final OsDistribution distroB = OsDistribution.of(new PackageURL(purl));
            assertThat(distroB).isNotNull();

            assertThat(distroA.matches(distroB)).isEqualTo(shouldMatch);
            assertThat(distroB.matches(distroA)).isEqualTo(shouldMatch);
        }

        @Test
        void shouldMatchMajorVersionWithPointRelease() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-11.6"));
            final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-11"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldMatchCodenameWithVersion() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=wheezy"));
            final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-7"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNotMatchDifferentMajorVersions() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-11"));
            final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-7"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
        }

    }

    @Nested
    class UnknownFallbackTest {

        @Test
        void shouldFallbackForUnknownVersion() {
            final DebianDistribution distro = DebianDistribution.of("666");
            assertThat(distro).isNotNull();
            assertThat(distro.series()).isEqualTo("666");
            assertThat(distro.version()).isEqualTo("666");
            assertThat(distro.purlQualifierValue()).isEqualTo("debian-666");
        }

        @Test
        void shouldFallbackForUnknownCodename() {
            final DebianDistribution distro = DebianDistribution.of("foo");
            assertThat(distro).isNotNull();
            assertThat(distro.series()).isEqualTo("foo");
            assertThat(distro.version()).isNull();
            assertThat(distro.purlQualifierValue()).isEqualTo("debian-foo");
        }

        @Test
        void shouldMatchUnknownVersions() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/curl@8.0?distro=debian-99"));
            final DebianDistribution distroB = DebianDistribution.of("99");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldMatchUnknownCodenames() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/curl@8.0?distro=zzz"));
            final DebianDistribution distroB = DebianDistribution.of("zzz");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNotMatchUnknownVersionWithCodename() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/curl@8.0?distro=debian-666"));
            final DebianDistribution distroB = DebianDistribution.of("foo");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
        }

    }

}
