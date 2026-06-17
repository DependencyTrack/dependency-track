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
