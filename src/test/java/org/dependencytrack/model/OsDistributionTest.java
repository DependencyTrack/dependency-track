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

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.OsDistribution.DebianDistribution;
import org.dependencytrack.model.OsDistribution.UbuntuDistribution;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class OsDistributionTest {

    @Nested
    class OfPurlTest {

        @ParameterizedTest
        @CsvSource(value = {
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?arch=amd64&distro=debian-11.6, DebianDistribution, debian-11",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=debian-11, DebianDistribution, debian-11",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=debian-7, DebianDistribution, debian-7",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=bullseye, DebianDistribution, debian-11",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=debian-bullseye, DebianDistribution, debian-11",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=debian-sid, DebianDistribution, debian-sid",
                "pkg:deb/debian/sudo@1.9.5p2-3%2Bdeb11u1?distro=sid, DebianDistribution, debian-sid",
                "pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04, UbuntuDistribution, ubuntu-22.04",
                "pkg:deb/ubuntu/sudo@1.9.5?distro=jammy, UbuntuDistribution, ubuntu-22.04",
                "pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-20.04, UbuntuDistribution, ubuntu-20.04",
                "pkg:deb/ubuntu/sudo@1.9.5?distro=focal, UbuntuDistribution, ubuntu-20.04",
                "pkg:apk/alpine/curl@8.5.0-r0?distro=alpine-3.16, AlpineDistribution, alpine-3.16",
                "pkg:apk/alpine/curl@8.5.0-r0?distro=3.16, AlpineDistribution, alpine-3.16",
                "pkg:apk/alpine/curl@8.5.0-r0?distro=3.16.4, AlpineDistribution, alpine-3.16",
                "pkg:apk/alpine/curl@8.5.0-r0?distro=alpine-3.18.5, AlpineDistribution, alpine-3.18",
        })
        void shouldParseDistro(String purl, String expectedType, String expectedPurlQualifier) throws Exception {
            final var packageUrl = new PackageURL(purl);

            final var distro = OsDistribution.of(packageUrl);
            assertThat(distro).isNotNull();
            assertThat(distro.getClass().getSimpleName()).isEqualTo(expectedType);
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedPurlQualifier);
        }

        @Test
        void shouldReturnNullForNullPurl() {
            assertThat(OsDistribution.of(null)).isNull();
        }

        @Test
        void shouldReturnNullForPurlWithoutQualifiers() throws Exception {
            final var purl = new PackageURL("pkg:deb/debian/sudo@1.9.5p2-3");
            assertThat(OsDistribution.of(purl)).isNull();
        }

        @Test
        void shouldReturnNullForPurlWithoutDistroQualifier() throws Exception {
            final var purl = new PackageURL("pkg:deb/debian/sudo@1.9.5p2-3?arch=amd64");
            assertThat(OsDistribution.of(purl)).isNull();
        }

        @Test
        void shouldReturnNullForNonDebianPurl() throws Exception {
            final var purl = new PackageURL("pkg:npm/lodash@4.17.21?distro=debian-11");
            assertThat(OsDistribution.of(purl)).isNull();
        }
    }

    @Nested
    class FromEcosystemTest {

        @ParameterizedTest
        @CsvSource(value = {
                "Debian:7, DebianDistribution, debian-7",
                "Debian:11, DebianDistribution, debian-11",
                "Debian:sid, DebianDistribution, debian-sid",
                "Debian:wheezy, DebianDistribution, debian-7",
                "Debian:bullseye, DebianDistribution, debian-11",
                "debian:11, DebianDistribution, debian-11",
        })
        void shouldParseEcosystemSuffix(String ecosystem, String expectedType, String expectedPurlQualifier) {
            final var distro = OsDistribution.ofOsvEcosystem(ecosystem);
            assertThat(distro).isNotNull();
            assertThat(distro.getClass().getSimpleName()).isEqualTo(expectedType);
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedPurlQualifier);
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"Debian", "Debian:", "PyPI", "npm"})
        void shouldReturnNullForInvalidEcosystem(String ecosystem) {
            assertThat(OsDistribution.ofOsvEcosystem(ecosystem)).isNull();
        }

        @Test
        void shouldReturnNullForUnknownEcosystem() {
            assertThat(OsDistribution.ofOsvEcosystem("Fedora:38")).isNull();
        }

        @ParameterizedTest
        @CsvSource(value = {
                "Ubuntu:22.04, ubuntu-22.04",
                "Ubuntu:20.04, ubuntu-20.04",
                "Ubuntu:jammy, ubuntu-22.04",
                "Ubuntu:focal, ubuntu-20.04",
                "ubuntu:22.04, ubuntu-22.04",
                "Ubuntu:16.04:LTS, ubuntu-16.04",
                "Ubuntu:22.04:LTS, ubuntu-22.04",
                "Ubuntu:14.04:LTS, ubuntu-14.04",
        })
        void shouldParseUbuntuEcosystemSuffix(String ecosystem, String expectedPurlQualifier) {
            final var distro = OsDistribution.ofOsvEcosystem(ecosystem);
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(UbuntuDistribution.class);
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedPurlQualifier);
        }

        @ParameterizedTest
        @CsvSource(value = {
                "Alpine:v3.5, alpine-3.5",
                "Alpine:v3.16, alpine-3.16",
                "Alpine:v3.22, alpine-3.22",
                "alpine:v3.18, alpine-3.18",
                "Alpine:3.16, alpine-3.16",
        })
        void shouldParseAlpineEcosystemSuffix(String ecosystem, String expectedPurlQualifier) {
            final var distro = OsDistribution.ofOsvEcosystem(ecosystem);
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(OsDistribution.AlpineDistribution.class);
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedPurlQualifier);
        }
    }

    @Nested
    class MatchesTest {

        @ParameterizedTest
        @CsvSource(value = {
                "Debian:7, pkg:deb/debian/apt?distro=debian-7, true",
                "Debian:7, pkg:deb/debian/apt?distro=debian-7.11, true",
                "Debian:7, pkg:deb/debian/apt?distro=wheezy, true",
                "Debian:7, pkg:deb/debian/apt?distro=debian-wheezy, true",
                "Debian:11, pkg:deb/debian/apt?distro=debian-11, true",
                "Debian:11, pkg:deb/debian/apt?distro=debian-11.6, true",
                "Debian:11, pkg:deb/debian/apt?distro=bullseye, true",
                "Debian:bullseye, pkg:deb/debian/apt?distro=debian-11, true",
                "Debian:sid, pkg:deb/debian/apt?distro=debian-sid, true",
                "Debian:sid, pkg:deb/debian/apt?distro=sid, true",
                "Debian:7, pkg:deb/debian/apt?distro=debian-11, false",
                "Debian:11, pkg:deb/debian/apt?distro=debian-7, false",
                "Debian:wheezy, pkg:deb/debian/apt?distro=debian-bullseye, false",
                "Debian:sid, pkg:deb/debian/apt?distro=debian-11, false",
        })
        void shouldMatch(String ecosystem, String purl, boolean shouldMatch) throws Exception {
            final var ecosystemDistro = OsDistribution.ofOsvEcosystem(ecosystem);
            assertThat(ecosystemDistro).isNotNull();

            final var qualifierDistro = OsDistribution.of(new PackageURL(purl));
            assertThat(qualifierDistro).isNotNull();

            assertThat(ecosystemDistro.matches(qualifierDistro)).isEqualTo(shouldMatch);
            assertThat(qualifierDistro.matches(ecosystemDistro)).isEqualTo(shouldMatch);
        }

        @Test
        void shouldMatchMajorVersionWithPointRelease() throws Exception {
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-11.6"));
            final var distroB = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-11"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldMatchCodenameWithVersion() throws Exception {
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=wheezy"));
            final var distroB = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-7"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNotMatchDifferentMajorVersions() throws Exception {
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-11"));
            final var distroB = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-7"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
        }

        @Test
        void shouldMatchUbuntuVersionWithCodename() throws Exception {
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04"));
            final var distroB = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=jammy"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNotMatchDifferentUbuntuVersions() throws Exception {
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04"));
            final var distroB = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-20.04"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
        }

        @Test
        void shouldNotMatchDebianWithUbuntu() throws Exception {
            final var debian = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-11"));
            final var ubuntu = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04"));

            assertThat(debian).isNotNull();
            assertThat(ubuntu).isNotNull();
            assertThat(debian.matches(ubuntu)).isFalse();
            assertThat(ubuntu.matches(debian)).isFalse();
        }

        @Test
        void shouldMatchAlpineMajorMinorVersions() throws Exception {
            final var distroA = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=3.16.4"));
            final var distroB = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=alpine-3.16"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNotMatchDifferentAlpineMinorVersions() throws Exception {
            final var distroA = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=3.16"));
            final var distroB = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=3.18"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
        }

        @Test
        void shouldNotMatchAlpineWithDebian() throws Exception {
            final var alpine = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=3.16"));
            final var debian = OsDistribution.of(new PackageURL("pkg:deb/debian/curl@8.5.0?distro=debian-11"));

            assertThat(alpine).isNotNull();
            assertThat(debian).isNotNull();
            assertThat(alpine.matches(debian)).isFalse();
            assertThat(debian.matches(alpine)).isFalse();
        }

    }

    @Nested
    class DebianDistributionKnownReleasesTest {

        @ParameterizedTest
        @CsvSource(value = {
                "1.1, buzz,",
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
        void shouldResolveKnownReleasesFromVersion(String version, String expectedSeries) {
            final var distro = OsDistribution.ofOsvEcosystem("Debian:" + version);
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(DebianDistribution.class);

            final var debian = (DebianDistribution) distro;
            assertThat(debian.series()).isEqualTo(expectedSeries);
            assertThat(debian.version()).isEqualTo(version);
        }

        @Test
        void shouldHandleSidWithNoVersion() {
            final var distro = OsDistribution.ofOsvEcosystem("Debian:sid");
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(DebianDistribution.class);

            final var debian = (DebianDistribution) distro;
            assertThat(debian.series()).isEqualTo("sid");
            assertThat(debian.version()).isNull();
            assertThat(debian.purlQualifierValue()).isEqualTo("debian-sid");
        }
    }

    @Nested
    class UnknownDistributionFallbackTest {

        @Test
        void shouldFallbackForUnknownDebianVersion() {
            final var distro = OsDistribution.ofOsvEcosystem("Debian:666");
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(DebianDistribution.class);

            final var debian = (DebianDistribution) distro;
            assertThat(debian.series()).isEqualTo("666");
            assertThat(debian.version()).isEqualTo("666");
            assertThat(debian.purlQualifierValue()).isEqualTo("debian-666");
        }

        @Test
        void shouldFallbackForUnknownDebianCodename() {
            final var distro = OsDistribution.ofOsvEcosystem("Debian:duke");
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(DebianDistribution.class);

            final var debian = (DebianDistribution) distro;
            assertThat(debian.series()).isEqualTo("duke");
            assertThat(debian.version()).isEqualTo("duke");
            assertThat(debian.purlQualifierValue()).isEqualTo("debian-duke");
        }

        @Test
        void shouldMatchUnknownDebianVersions() throws Exception {
            // Both sides use same unknown version - should match
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/curl@8.0?distro=debian-15"));
            final var distroB = OsDistribution.ofOsvEcosystem("Debian:15");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldMatchUnknownDebianCodenames() throws Exception {
            // Both sides use same unknown codename - should match
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/curl@8.0?distro=duke"));
            final var distroB = OsDistribution.ofOsvEcosystem("Debian:duke");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNotMatchUnknownDebianVersionWithCodename() throws Exception {
            // Version "15" vs codename "duke" - can't resolve mapping, won't match
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/debian/curl@8.0?distro=debian-15"));
            final var distroB = OsDistribution.ofOsvEcosystem("Debian:duke");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
        }

        @Test
        void shouldFallbackForUnknownUbuntuVersion() {
            final var distro = OsDistribution.ofOsvEcosystem("Ubuntu:66.66");
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(UbuntuDistribution.class);

            final var ubuntu = (UbuntuDistribution) distro;
            assertThat(ubuntu.series()).isEqualTo("66.66");
            assertThat(ubuntu.version()).isEqualTo("66.66");
            assertThat(ubuntu.purlQualifierValue()).isEqualTo("ubuntu-66.66");
        }

        @Test
        void shouldFallbackForUnknownUbuntuSeries() {
            final var distro = OsDistribution.ofOsvEcosystem("Ubuntu:xyz");
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(UbuntuDistribution.class);

            final var ubuntu = (UbuntuDistribution) distro;
            assertThat(ubuntu.series()).isEqualTo("xyz");
            assertThat(ubuntu.version()).isEqualTo("xyz");
            assertThat(ubuntu.purlQualifierValue()).isEqualTo("ubuntu-xyz");
        }

        @Test
        void shouldMatchUnknownUbuntuVersions() throws Exception {
            // Both sides use same unknown version - should match
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/curl@8.0?distro=ubuntu-28.04"));
            final var distroB = OsDistribution.ofOsvEcosystem("Ubuntu:28.04");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNotMatchUnknownUbuntuVersionWithSeries() throws Exception {
            // Version "28.04" vs series "xyz" - can't resolve mapping, won't match
            final var distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/curl@8.0?distro=ubuntu-28.04"));
            final var distroB = OsDistribution.ofOsvEcosystem("Ubuntu:xyz");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
        }
    }

}
