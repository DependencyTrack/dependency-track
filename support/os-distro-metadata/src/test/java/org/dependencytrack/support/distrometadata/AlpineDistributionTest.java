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

import static org.assertj.core.api.Assertions.assertThat;

class AlpineDistributionTest {

    @ParameterizedTest
    @CsvSource(value = {
            "pkg:apk/alpine/curl@8.5.0-r0?distro=alpine-3.16, alpine-3.16",
            "pkg:apk/alpine/curl@8.5.0-r0?distro=3.16, alpine-3.16",
            "pkg:apk/alpine/curl@8.5.0-r0?distro=3.16.4, alpine-3.16",
            "pkg:apk/alpine/curl@8.5.0-r0?distro=alpine-3.18.5, alpine-3.18",
    })
    void shouldParseFromPurl(String purl, String expectedQualifier) throws Exception {
        final OsDistribution distro = OsDistribution.of(new PackageURL(purl));
        assertThat(distro).isNotNull();
        assertThat(distro).isInstanceOf(AlpineDistribution.class);
        assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
    }

    @ParameterizedTest
    @CsvSource(value = {
            "v3.5, alpine-3.5",
            "v3.16, alpine-3.16",
            "v3.22, alpine-3.22",
            "v3.18, alpine-3.18",
            "3.16, alpine-3.16",
            "3.16.4, alpine-3.16",
    })
    void shouldParseFromVersion(String version, String expectedQualifier) {
        final AlpineDistribution distro = AlpineDistribution.ofVersion(version);
        assertThat(distro).isNotNull();
        assertThat(distro.purlQualifierValue()).isEqualTo(expectedQualifier);
    }

    @Test
    void shouldMatchMajorMinorVersions() throws Exception {
        final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=3.16.4"));
        final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=alpine-3.16"));

        assertThat(distroA).isNotNull();
        assertThat(distroB).isNotNull();
        assertThat(distroA.matches(distroB)).isTrue();
    }

    @Test
    void shouldNotMatchDifferentMinorVersions() throws Exception {
        final OsDistribution distroA = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=3.16"));
        final OsDistribution distroB = OsDistribution.of(new PackageURL("pkg:apk/alpine/curl@8.5.0?distro=3.18"));

        assertThat(distroA).isNotNull();
        assertThat(distroB).isNotNull();
        assertThat(distroA.matches(distroB)).isFalse();
    }

}
