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

import static org.assertj.core.api.Assertions.assertThat;

class OsDistributionTest {

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
    void shouldReturnNullForPurlOfUnsupportedType() throws Exception {
        final var purl = new PackageURL("pkg:npm/lodash@4.17.21?distro=debian-11");
        assertThat(OsDistribution.of(purl)).isNull();
    }

    @Test
    void shouldReturnNullForDebPurlWithUnknownNamespace() throws Exception {
        final var purl = new PackageURL("pkg:deb/raspbian/sudo@1.9.5?distro=raspbian-11");
        assertThat(OsDistribution.of(purl)).isNull();
    }

    @Test
    void shouldNotMatchDebianWithUbuntu() throws Exception {
        final OsDistribution debian = OsDistribution.of(new PackageURL("pkg:deb/debian/sudo@1.9.5?distro=debian-11"));
        final OsDistribution ubuntu = OsDistribution.of(new PackageURL("pkg:deb/ubuntu/sudo@1.9.5?distro=ubuntu-22.04"));

        assertThat(debian).isNotNull();
        assertThat(ubuntu).isNotNull();
        assertThat(debian.matches(ubuntu)).isFalse();
        assertThat(ubuntu.matches(debian)).isFalse();
    }

    @Test
    void shouldNotMatchAlpineWithDebian() throws Exception {
        final OsDistribution alpine = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=3.16"));
        final OsDistribution debian = OsDistribution.of(new PackageURL("pkg:deb/debian/curl@8.5.0?distro=debian-11"));

        assertThat(alpine).isNotNull();
        assertThat(debian).isNotNull();
        assertThat(alpine.matches(debian)).isFalse();
        assertThat(debian.matches(alpine)).isFalse();
    }

}
