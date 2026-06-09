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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class RedhatDistributionTest {

    @ParameterizedTest
    @CsvSource(value = {
            "pkg:rpm/redhat/libsolv@0.7.24-3.el9?distro=redhat-9.7, redhat-9",
            "pkg:rpm/redhat/libsolv@0.7.24-3.el9?distro=9.7, redhat-9",
            "pkg:rpm/redhat/libsolv@0.7.24-3.el8?distro=redhat-8, redhat-8",
            "pkg:rpm/redhat/libsolv@0.7.24-3.el8?distro=redhat-8.4, redhat-8",
    })
    void shouldParseFromPurl(String purl, String expectedQualifier) throws Exception {
        final OsDistribution distro = OsDistribution.of(new PackageURL(purl));
        assertThat(distro).isNotNull();
        assertThat(distro).isInstanceOf(RedhatDistribution.class);
        assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
    }

    @ParameterizedTest
    @CsvSource(value = {
            "redhat-9.7, redhat-9",
            "9.7, redhat-9",
            "8, redhat-8",
    })
    void shouldParseFromQualifierValue(String value, String expectedQualifier) {
        final RedhatDistribution distro = RedhatDistribution.of(value);
        assertThat(distro).isNotNull();
        assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
    }

    @ParameterizedTest
    @CsvSource(value = {
            // RHEL-family products carry the RHEL major in their version field.
            "rhel_aus:8.4::appstream, redhat-8",
            "rhel:9::appstream, redhat-9",
            "rhel_eus:8.6::baseos, redhat-8",
            "enterprise_linux:8::baseos, redhat-8",
            // Layered products carry their own version; the RHEL major is the
            // explicit "elN" OS target, NOT the product version (#6156 review).
            "openshift:4.18::el8, redhat-8",
            "openshift_container_platform:4.18::el9, redhat-9",
            "satellite:6.16::el8, redhat-8",
            "satellite_capsule:6.16::el8, redhat-8",
            "rhel_sat:6.15::el8, redhat-8",
    })
    void shouldParseFromCpe(String cpe, String expectedQualifier) {
        final RedhatDistribution distro = RedhatDistribution.ofCpe(cpe);
        assertThat(distro).isNotNull();
        assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            "rhel_aus",          // RHEL product, but no version
            "appstream",         // no product, no version
            "noversion",
            "openshift:4.18",                 // layered product without an elN OS target
            "satellite:6.16",
            "rhel_application_stack:2",        // product stream version is NOT the RHEL major
            "rhel_application_server:1",
            "rhel_atomic:7",                   // RHEL Atomic stream, not a base RHEL major
    })
    void shouldReturnNullForCpeWithoutResolvableRhelMajor(String cpe) {
        assertThat(RedhatDistribution.ofCpe(cpe)).isNull();
    }

    @Test
    void shouldMatchSameMajorVersion() throws Exception {
        final OsDistribution component = OsDistribution.of(
                new PackageURL("pkg:rpm/redhat/libsolv@0.7.24-3.el9?distro=redhat-9.7"));
        final RedhatDistribution advisory = RedhatDistribution.ofCpe("rhel_aus:9.0::appstream");

        assertThat(component).isNotNull();
        assertThat(advisory).isNotNull();
        assertThat(component.matches(advisory)).isTrue();
    }

    @Test
    void shouldNotMatchDifferentMajorVersion() throws Exception {
        // Regression for #6156: a RHEL 9 component must not match an advisory
        // scoped to a RHEL 8 (e.g. el8sat) product stream.
        final OsDistribution component = OsDistribution.of(
                new PackageURL("pkg:rpm/redhat/libsolv@0.7.24-3.el9?distro=redhat-9.7"));
        final RedhatDistribution advisory = RedhatDistribution.ofCpe("rhel_aus:8.0::baseos");

        assertThat(component).isNotNull();
        assertThat(advisory).isNotNull();
        assertThat(component.matches(advisory)).isFalse();
    }

    @Test
    void shouldReturnNullForRpmWithoutRedhatNamespace() throws Exception {
        final var purl = new PackageURL("pkg:rpm/fedora/curl@8.5.0?distro=fedora-38");
        assertThat(OsDistribution.of(purl)).isNull();
    }

    @Test
    void shouldReturnNullForRedhatPurlWithoutDistroQualifier() throws Exception {
        final var purl = new PackageURL("pkg:rpm/redhat/libsolv@0.7.24-3.el9?arch=x86_64");
        assertThat(OsDistribution.of(purl)).isNull();
    }

    @Test
    void shouldNotMatchRedhatWithAlpine() throws Exception {
        final OsDistribution redhat = OsDistribution.of(
                new PackageURL("pkg:rpm/redhat/libsolv@0.7.24-3.el9?distro=redhat-9.7"));
        final OsDistribution alpine = OsDistribution.of(
                new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=3.16"));

        assertThat(redhat).isNotNull();
        assertThat(alpine).isNotNull();
        assertThat(redhat.matches(alpine)).isFalse();
        assertThat(alpine.matches(redhat)).isFalse();
    }

}
