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
package org.dependencytrack.vulndatasource.osv;

import org.dependencytrack.support.distrometadata.AlpineDistribution;
import org.dependencytrack.support.distrometadata.DebianDistribution;
import org.dependencytrack.support.distrometadata.OsDistribution;
import org.dependencytrack.support.distrometadata.UbuntuDistribution;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class OsvEcosystemsTest {

    @ParameterizedTest
    @CsvSource(value = {
            "Debian:7, DebianDistribution, debian-7",
            "Debian:11, DebianDistribution, debian-11",
            "Debian:sid, DebianDistribution, debian-sid",
            "Debian:wheezy, DebianDistribution, debian-7",
            "Debian:bullseye, DebianDistribution, debian-11",
            "debian:11, DebianDistribution, debian-11",
            "Ubuntu:22.04, UbuntuDistribution, ubuntu-22.04",
            "Ubuntu:20.04, UbuntuDistribution, ubuntu-20.04",
            "Ubuntu:jammy, UbuntuDistribution, ubuntu-22.04",
            "Ubuntu:focal, UbuntuDistribution, ubuntu-20.04",
            "ubuntu:22.04, UbuntuDistribution, ubuntu-22.04",
            "Ubuntu:16.04:LTS, UbuntuDistribution, ubuntu-16.04",
            "Ubuntu:22.04:LTS, UbuntuDistribution, ubuntu-22.04",
            "Ubuntu:14.04:LTS, UbuntuDistribution, ubuntu-14.04",
            "Alpine:v3.5, AlpineDistribution, alpine-3.5",
            "Alpine:v3.16, AlpineDistribution, alpine-3.16",
            "Alpine:v3.22, AlpineDistribution, alpine-3.22",
            "alpine:v3.18, AlpineDistribution, alpine-3.18",
            "Alpine:3.16, AlpineDistribution, alpine-3.16",
            // Red Hat RHEL streams:
            "Red Hat:enterprise_linux:8::appstream, RedHatDistribution, redhat-8",
            "Red Hat:enterprise_linux:9::baseos, RedHatDistribution, redhat-9",
            "Red Hat:enterprise_linux:7::server, RedHatDistribution, redhat-7",
            "Red Hat:enterprise_linux:5::as, RedHatDistribution, redhat-5",
            "Red Hat:enterprise_linux_eus:10.0, RedHatDistribution, redhat-10",
            "Red Hat:rhel_aus:8.4::appstream, RedHatDistribution, redhat-8",
            "Red Hat:rhel_eus:9.2::baseos, RedHatDistribution, redhat-9",
            "Red Hat:rhel_e4s:8.2, RedHatDistribution, redhat-8",
            "Red Hat:rhel_tus:8.6::appstream, RedHatDistribution, redhat-8",
            "Red Hat:rhel_els:7, RedHatDistribution, redhat-7",
            "Red Hat:rhel_extras:6, RedHatDistribution, redhat-6",
            "red hat:enterprise_linux:9, RedHatDistribution, redhat-9",
            // Red Hat non-RHEL products:
            "Red Hat:satellite:6.13::el8, RedHatDistribution, redhat-8",
            "Red Hat:openshift:4.12::el9, RedHatDistribution, redhat-9",
            "Red Hat:openshift:4.8::el10, RedHatDistribution, redhat-10",
            "Red Hat:jboss_enterprise_application_platform:7.4::el8, RedHatDistribution, redhat-8",
            "Red Hat:ceph_storage:6.1::el9, RedHatDistribution, redhat-9",
            "Red Hat:openstack:17.1::el8, RedHatDistribution, redhat-8",
            "Red Hat:red_hat_single_sign_on:7::el6, RedHatDistribution, redhat-6",
            "Red Hat:ansible_automation_platform:2.5::el9, RedHatDistribution, redhat-9",
            // Red Hat rhel_* products that put their own version in the version field but
            // expose the RHEL major version via the edition:
            "Red Hat:rhel_software_collections:3::el7, RedHatDistribution, redhat-7",
            "Red Hat:rhel_dotnet:6.0::el7, RedHatDistribution, redhat-7",
            // Red Hat Edition with trailing variant suffix:
            "Red Hat:satellite:6.16::el8_sat, RedHatDistribution, redhat-8",
    })
    void shouldResolve(String ecosystem, String expectedType, String expectedQualifier) {
        final OsDistribution distro = OsvEcosystems.toOsDistribution(ecosystem);
        assertThat(distro).isNotNull();
        assertThat(distro.getClass().getSimpleName()).isEqualTo(expectedType);
        assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"Debian", "Debian:", "PyPI", "npm"})
    void shouldReturnNullForInvalidEcosystem(String ecosystem) {
        assertThat(OsvEcosystems.toOsDistribution(ecosystem)).isNull();
    }

    @Test
    void shouldReturnNullForUnknownEcosystem() {
        assertThat(OsvEcosystems.toOsDistribution("Fedora:38")).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Red Hat:",
            "Red Hat:enterprise_linux",
            "Red Hat:not a cpe",
            "Red Hat:satellite:6.13",
            "Red Hat:openshift:4.12::fastdatapath",
    })
    void shouldReturnNullForInvalidRedHatEcosystem(String ecosystem) {
        assertThat(OsvEcosystems.toOsDistribution(ecosystem)).isNull();
    }

    @Test
    void shouldFallbackForUnknownDebianVersion() {
        final OsDistribution distro = OsvEcosystems.toOsDistribution("Debian:666");
        assertThat(distro).isInstanceOf(DebianDistribution.class);
        final DebianDistribution debian = (DebianDistribution) distro;
        assertThat(debian.series()).isEqualTo("666");
        assertThat(debian.version()).isEqualTo("666");
    }

    @Test
    void shouldFallbackForUnknownDebianCodename() {
        final OsDistribution distro = OsvEcosystems.toOsDistribution("Debian:foo");
        assertThat(distro).isInstanceOf(DebianDistribution.class);
        final DebianDistribution debian = (DebianDistribution) distro;
        assertThat(debian.series()).isEqualTo("foo");
        assertThat(debian.version()).isNull();
    }

    @Test
    void shouldFallbackForUnknownUbuntuVersion() {
        final OsDistribution distro = OsvEcosystems.toOsDistribution("Ubuntu:66.66");
        assertThat(distro).isInstanceOf(UbuntuDistribution.class);
        final UbuntuDistribution ubuntu = (UbuntuDistribution) distro;
        assertThat(ubuntu.version()).isEqualTo("66.66");
    }

    @Test
    void shouldFallbackForUnknownUbuntuSeries() {
        final OsDistribution distro = OsvEcosystems.toOsDistribution("Ubuntu:xyz");
        assertThat(distro).isInstanceOf(UbuntuDistribution.class);
        final UbuntuDistribution ubuntu = (UbuntuDistribution) distro;
        assertThat(ubuntu.series()).isEqualTo("xyz");
    }

    @Test
    void shouldStripUbuntuProSuffix() {
        final OsDistribution distro = OsvEcosystems.toOsDistribution("Ubuntu:22.04:Pro");
        assertThat(distro).isInstanceOf(UbuntuDistribution.class);
        assertThat(distro.purlQualifierValue()).isEqualTo("ubuntu-22.04");
    }

    @Test
    void shouldHandleAlpineWithoutPrefix() {
        final OsDistribution distro = OsvEcosystems.toOsDistribution("Alpine:3.16.4");
        assertThat(distro).isInstanceOf(AlpineDistribution.class);
        assertThat(distro.purlQualifierValue()).isEqualTo("alpine-3.16");
    }

}
