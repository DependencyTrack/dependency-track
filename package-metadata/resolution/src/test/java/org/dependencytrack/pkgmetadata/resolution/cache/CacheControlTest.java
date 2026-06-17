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
package org.dependencytrack.pkgmetadata.resolution.cache;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CacheControlTest {

    @Test
    void shouldReturnAbsentWhenHeaderListIsEmpty() {
        assertThat(CacheControl.of(List.of())).isSameAs(CacheControl.ABSENT);
    }

    @Test
    void shouldParseMaxAgeAndPublic() {
        final CacheControl directives = CacheControl.of(List.of("public, max-age=60"));

        assertThat(directives.noStore()).isFalse();
        assertThat(directives.noCache()).isFalse();
        assertThat(directives.maxAgeSeconds()).isEqualTo(60L);
    }

    @Test
    void shouldParseNoStore() {
        final CacheControl directives = CacheControl.of(List.of("no-store"));

        assertThat(directives.noStore()).isTrue();
        assertThat(directives.noCache()).isFalse();
        assertThat(directives.maxAgeSeconds()).isNull();
    }

    @Test
    void shouldParseNoCacheAsNoCache() {
        assertThat(CacheControl.of(List.of("no-cache")).noCache()).isTrue();
    }

    @Test
    void shouldNotTreatMustRevalidateAsNoCache() {
        // RFC 9111: must-revalidate only forbids serving stale, freshness is still
        // governed by max-age. Treating it as no-cache would defeat max-age.
        final CacheControl directives = CacheControl.of(List.of("must-revalidate, max-age=60"));

        assertThat(directives.noCache()).isFalse();
        assertThat(directives.maxAgeSeconds()).isEqualTo(60L);
    }

    @Test
    void shouldIgnoreUnknownDirectives() {
        final CacheControl directives = CacheControl.of(
                List.of("max-age=300, immutable, stale-while-revalidate=10"));

        assertThat(directives.maxAgeSeconds()).isEqualTo(300L);
        assertThat(directives.noStore()).isFalse();
        assertThat(directives.noCache()).isFalse();
    }

    @Test
    void shouldMatchDirectiveNamesCaseInsensitively() {
        final CacheControl directives = CacheControl.of(List.of("No-Store, Max-Age=42"));

        assertThat(directives.noStore()).isTrue();
        assertThat(directives.maxAgeSeconds()).isEqualTo(42L);
    }

    @Test
    void shouldStripQuotesFromMaxAgeArgument() {
        assertThat(CacheControl.of(List.of("max-age=\"15\"")).maxAgeSeconds()).isEqualTo(15L);
    }

    @Test
    void shouldTreatMalformedMaxAgeAsAbsent() {
        assertThat(CacheControl.of(List.of("max-age=abc")).maxAgeSeconds()).isNull();
    }

    @Test
    void shouldTreatNegativeMaxAgeAsAbsent() {
        assertThat(CacheControl.of(List.of("max-age=-5")).maxAgeSeconds()).isNull();
    }

    @Test
    void shouldMergeAcrossMultipleHeaderValues() {
        final CacheControl directives = CacheControl.of(
                List.of("no-cache", "max-age=120"));

        assertThat(directives.noCache()).isTrue();
        assertThat(directives.maxAgeSeconds()).isEqualTo(120L);
    }

    @Test
    void shouldIgnoreBlankTokens() {
        final CacheControl directives = CacheControl.of(List.of(",,, max-age=10 ,"));

        assertThat(directives.maxAgeSeconds()).isEqualTo(10L);
    }

}
