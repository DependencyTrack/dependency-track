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
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class RedHatDistributionTest {

    @Nested
    class OfQualifierValueTest {

        @ParameterizedTest
        @CsvSource(value = {
                "pkg:rpm/redhat/sudo@1.9.5?distro=rhel-9, redhat-9",
                "pkg:rpm/redhat/sudo@1.9.5?distro=rhel-8.6, redhat-8",
                "pkg:rpm/redhat/sudo@1.9.5?distro=redhat-9.7, redhat-9",
                "pkg:rpm/redhat/sudo@1.9.5?distro=9.2, redhat-9",
                "pkg:rpm/redhat/sudo@1.9.5?distro=RHEL-9, redhat-9",
        })
        void shouldParseFromPurl(String purl, String expectedQualifier) throws Exception {
            final OsDistribution distro = OsDistribution.of(new PackageURL(purl));
            assertThat(distro).isNotNull();
            assertThat(distro).isInstanceOf(RedHatDistribution.class);
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {"foo", "rhel-", "redhat-", "*", "abc-9", "9abc"})
        void shouldReturnNullForInvalidQualifier(String qualifier) {
            assertThat(RedHatDistribution.of(qualifier)).isNull();
        }

    }

    @Nested
    class OfVersionTest {

        @ParameterizedTest
        @CsvSource(value = {
                "9, redhat-9",
                "8, redhat-8",
                "8.6, redhat-8",
                "9.2.0, redhat-9",
        })
        void shouldParseFromVersion(String version, String expectedQualifier) {
            final RedHatDistribution distro = RedHatDistribution.ofVersion(version);
            assertThat(distro).isNotNull();
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
        }

    }

    @Nested
    class OfCpeTest {

        @ParameterizedTest
        @CsvSource(value = {
                "rhel_aus:8.4::appstream, redhat-8",
                "rhel_eus:9.2::baseos, redhat-9",
                "rhel_e4s:8.2, redhat-8",
                "rhel_els:7, redhat-7",
                "rhel_extras:6, redhat-6",
                "enterprise_linux:8::baseos, redhat-8",
                "enterprise_linux:9::appstream, redhat-9",
                "enterprise_linux_eus:10.0, redhat-10",
                "openshift:4.18::el8, redhat-8",
                "openshift_container_platform:4.18::el9, redhat-9",
                "satellite:6.16::el8, redhat-8",
                "satellite_capsule:6.16::el8, redhat-8",
                "jboss_enterprise_application_platform:7.4::el8, redhat-8",
                "rhel_software_collections:3::el7, redhat-7",
                "rhel_dotnet:6.0::el7, redhat-7",
                "satellite:6.16::el8_sat, redhat-8",
        })
        void shouldParseFromCpe(String cpe, String expectedQualifier) {
            final RedHatDistribution distro = RedHatDistribution.ofCpe(cpe);
            assertThat(distro).isNotNull();
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {
                "rhel_aus",
                "appstream",
                "noversion",
                "openshift:4.18",
                "satellite:6.16",
                "openshift:4.12::fastdatapath",
                "rhel_application_stack:2",
                "rhel_application_server:1",
                "rhel_atomic:7",
        })
        void shouldReturnNullForCpeWithoutResolvableRhelMajor(String cpe) {
            assertThat(RedHatDistribution.ofCpe(cpe)).isNull();
        }

    }

    @Nested
    class OfRpmReleaseTest {

        @ParameterizedTest
        @CsvSource(value = {
                "0.7.24-3.el9, redhat-9",
                "2.34-125.el9_5.8, redhat-9",
                "0.7.20-6.el8sat, redhat-8",
                "1.module+el8.7.0+12345+abcdef1, redhat-8",
                "1-1.el10, redhat-10",
                "1.0-3.el8_6.cve_2021_44228, redhat-8",
                "1:0.7.20-6.el8sat, redhat-8",
                "el9, redhat-9",
        })
        void shouldExtractFromRpmRelease(String version, String expectedQualifier) {
            final RedHatDistribution distro = RedHatDistribution.ofRpmRelease(version);
            assertThat(distro).isNotNull();
            assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {
                "1.0", "1.0-3",
                "1.0-3.fc35",
                "1.0-1.amzn2023",
                "1.0-1.mga9",
                "model-1.0",
        })
        void shouldReturnNullWhenRpmReleaseHasNoDisttag(String version) {
            assertThat(RedHatDistribution.ofRpmRelease(version)).isNull();
        }

    }

    @Nested
    class MatchesTest {

        @Test
        void shouldMatchOnMajorVersionAcrossMinor() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:rpm/redhat/sudo@1.9.5?distro=rhel-8.6"));
            final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:rpm/redhat/sudo@1.9.5?distro=rhel-8"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
            assertThat(distroB.matches(distroA)).isTrue();
        }

        @Test
        void shouldMatchRhelAndRedhatPrefixForSameMajor() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:rpm/redhat/sudo@1.9.5?distro=rhel-9"));
            final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:rpm/redhat/sudo@1.9.5?distro=redhat-9.7"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isTrue();
            assertThat(distroB.matches(distroA)).isTrue();
        }

        @Test
        void shouldMatchComponentWithRhelPrefixAgainstCpe() throws Exception {
            final OsDistribution component = OsDistribution.of(new PackageURL("pkg:rpm/redhat/libsolv@0.7.24-3.el8?distro=rhel-8"));
            final RedHatDistribution advisory = RedHatDistribution.ofCpe("rhel_aus:8.4::appstream");

            assertThat(component).isNotNull();
            assertThat(advisory).isNotNull();
            assertThat(component.matches(advisory)).isTrue();
            assertThat(advisory.matches(component)).isTrue();
        }

        @Test
        void shouldNotMatchComponentAgainstCpeOfDifferentMajor() throws Exception {
            final OsDistribution component = OsDistribution.of(new PackageURL("pkg:rpm/redhat/libsolv@0.7.24-3.el9?distro=redhat-9.7"));
            final RedHatDistribution advisory = RedHatDistribution.ofCpe("rhel_aus:8.0::baseos");

            assertThat(component).isNotNull();
            assertThat(advisory).isNotNull();
            assertThat(component.matches(advisory)).isFalse();
            assertThat(advisory.matches(component)).isFalse();
        }

        @Test
        void shouldNotMatchDifferentMajorVersions() throws Exception {
            final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:rpm/redhat/sudo@1.9.5?distro=rhel-8"));
            final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:rpm/redhat/sudo@1.9.5?distro=rhel-9"));

            assertThat(distroA).isNotNull();
            assertThat(distroB).isNotNull();
            assertThat(distroA.matches(distroB)).isFalse();
            assertThat(distroB.matches(distroA)).isFalse();
        }

    }

}
