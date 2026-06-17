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
package org.dependencytrack.util;

import com.github.packageurl.PackageURL;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class PurlUtilTest {

    @Test
    public void testSilentPurlWithNull() {
        assertThat(PurlUtil.silentPurl(null)).isNull();
    }

    @Test
    public void testSilentPurlWithInvalidPurl() {
        assertThat(PurlUtil.silentPurl("foo:bar:baz")).isNull();
    }

    @Test
    public void testSilentPurlWithValidPurl() {
        final PackageURL purl = PurlUtil.silentPurl("pkg:maven/foo/bar@1.2.3?qux=quux#baz");
        assertThat(purl).isNotNull();
        assertThat(purl.getType()).isEqualTo("maven");
        assertThat(purl.getNamespace()).isEqualTo("foo");
        assertThat(purl.getName()).isEqualTo("bar");
        assertThat(purl.getVersion()).isEqualTo("1.2.3");
        assertThat(purl.getSubpath()).isEqualTo("baz");
        assertThat(purl.getQualifiers()).containsOnly(Map.entry("qux", "quux"));
    }

}