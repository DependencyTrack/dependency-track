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

class UbuntuDistributionTest {

    @Nested
    class FromPurlTest {

        @ParameterizedTest
        @CsvSource(value = {
                "pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04, ubuntu-22.04",
                "pkg:deb/ubuntu/sudo@1.9.5?distro=jammy, ubuntu-22.04",
                "pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-20.04, ubuntu-20.04",
                "pkg:deb/ubuntu/sudo@1.9.5?distro=focal, ubuntu-20.04",
        })
        void shouldParse(String purl, String expectedQualifier) throws Exception {
            final OsDistribution distro = OsDistribution.of(new PackageURL(purl));
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(UbuntuDistribution.class);
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
        }

    }

    @Nested
    class KnownReleasesTest {

        @ParameterizedTest
        @CsvSource(value = {
                "22.04, jammy",
                "20.04, focal",
                "18.04, bionic",
                "16.04, xenial",
                "14.04, trusty",
                "12.04, precise",
                "10.04, lucid",
        })
        void shouldResolveFromVersion(String version, String expectedSeries) {
            final UbuntuDistribution distro = UbuntuDistribution.of(version);
            assertThat(distro).isNotNull();
            assertThat(distro.series()).isEqualTo(expectedSeries);
            assertThat(distro.version()).isEqualTo(version);
        }

    }

    @Nested
    class MatchesTest {

        @Test
        void shouldMatchVersionWithCodename() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04"));
            final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=jammy"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNotMatchDifferentVersions() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04"));
            final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-20.04"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
        }

    }

    @Nested
    class UnknownFallbackTest {

        @Test
        void shouldFallbackForUnknownVersion() {
            final UbuntuDistribution distro = UbuntuDistribution.of("66.66");
            assertThat(distro).isNotNull();
            assertThat(distro.series()).isEqualTo("66.66");
            assertThat(distro.version()).isEqualTo("66.66");
            assertThat(distro.purlQualifierValue()).isEqualTo("ubuntu-66.66");
        }

        @Test
        void shouldFallbackForUnknownSeries() {
            final UbuntuDistribution distro = UbuntuDistribution.of("xyz");
            assertThat(distro).isNotNull();
            assertThat(distro.series()).isEqualTo("xyz");
            assertThat(distro.version()).isEqualTo("xyz");
            assertThat(distro.purlQualifierValue()).isEqualTo("ubuntu-xyz");
        }

        @Test
        void shouldMatchUnknownVersions() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/curl@8.0?distro=ubuntu-28.04"));
            final UbuntuDistribution distroB = UbuntuDistribution.of("28.04");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNormalizePointRelease() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/curl@8.0?distro=ubuntu-22.04.4"));
            assertThat(distroA).isNotNull();
            assertThat(distroA).isInstanceOf(UbuntuDistribution.class);

            final UbuntuDistribution ubuntu = (UbuntuDistribution) distroA;
            assertThat(ubuntu.series()).isEqualTo("jammy");
            assertThat(ubuntu.version()).isEqualTo("22.04");
        }

        @Test
        void shouldMatchPointReleaseWithMajorMinor() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/curl@8.0?distro=ubuntu-22.04.4"));
            final UbuntuDistribution distroB = UbuntuDistribution.of("22.04");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
        }

        @Test
        void shouldNotMatchUnknownVersionWithSeries() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/curl@8.0?distro=ubuntu-28.04"));
            final UbuntuDistribution distroB = UbuntuDistribution.of("xyz");

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
        }

    }

}
