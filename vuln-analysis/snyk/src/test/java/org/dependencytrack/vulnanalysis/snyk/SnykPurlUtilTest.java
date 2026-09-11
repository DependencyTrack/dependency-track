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
package org.dependencytrack.vulnanalysis.snyk;

import com.github.packageurl.PackageURL;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SnykPurlUtilTest {

    @Test
    void shouldUseCoordinatesWhenChecksumMatchingDisabled() throws Exception {
        final var purl = new PackageURL(
                "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.Final?checksum=sha1:40fd4d696c55793e996d1ff3c475833f836c2498");

        assertThat(SnykPurlUtil.toSnykRequestPurl(purl, false))
                .isEqualTo("pkg:maven/org.jboss.logging/jboss-logging@3.4.1.final");
        assertThat(SnykPurlUtil.requiresChecksumMeta(purl, false)).isFalse();
    }

    @Test
    void shouldUseFullPurlForMavenWithChecksumWhenEnabled() throws Exception {
        final var purl = new PackageURL(
                "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.Final?checksum=sha1:40fd4d696c55793e996d1ff3c475833f836c2498");

        assertThat(SnykPurlUtil.requiresChecksumMeta(purl, true)).isTrue();
        assertThat(SnykPurlUtil.toSnykRequestPurl(purl, true))
                .isEqualTo(
                        "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.final?checksum=sha1%3a40fd4d696c55793e996d1ff3c475833f836c2498");
    }

    @Test
    void shouldUseCoordinatesForMavenWithoutChecksumWhenEnabled() throws Exception {
        final var purl = new PackageURL("pkg:maven/org.jboss.logging/jboss-logging@3.4.1.Final");

        assertThat(SnykPurlUtil.requiresChecksumMeta(purl, true)).isFalse();
        assertThat(SnykPurlUtil.toSnykRequestPurl(purl, true))
                .isEqualTo("pkg:maven/org.jboss.logging/jboss-logging@3.4.1.final");
    }

    @Test
    void shouldUseCoordinatesForNonMavenEvenWithChecksum() throws Exception {
        final var purl = new PackageURL(
                "pkg:npm/lodash@4.17.21?checksum=sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        assertThat(SnykPurlUtil.requiresChecksumMeta(purl, true)).isFalse();
        assertThat(SnykPurlUtil.toSnykRequestPurl(purl, true)).isEqualTo("pkg:npm/lodash@4.17.21");
    }

    @Test
    void shouldNormalizeEncodedAndUnencodedChecksumKeysToSameValue() {
        final String unencoded =
                "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.Final?checksum=sha1:40fd4d696c55793e996d1ff3c475833f836c2498";
        final String encoded =
                "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.Final?checksum=sha1%3A40fd4d696c55793e996d1ff3c475833f836c2498";

        assertThat(SnykPurlUtil.normalizePurlKey(unencoded)).isEqualTo(SnykPurlUtil.normalizePurlKey(encoded));
        assertThat(SnykPurlUtil.normalizePurlKey(unencoded))
                .isEqualTo(
                        "pkg:maven/org.jboss.logging/jboss-logging@3.4.1.final?checksum=sha1%3a40fd4d696c55793e996d1ff3c475833f836c2498");
    }
}
