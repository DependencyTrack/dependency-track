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
package org.dependencytrack.vulndatasource.nvd;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class NvdDataFeedMetadataTest {

    @Test
    void shouldParseLastModifiedDateAndSha256() {
        final NvdDataFeedMetadata metadata = NvdDataFeedMetadata.of("""
                lastModifiedDate:2026-01-19T16:00:01-05:00
                size:15114674
                zipSize:1674794
                gzSize:1674650
                sha256:482399306951B6FF9E00E3EC72A7EED8D927FB2DB4F4E61F2D6218CF67133CC0
                """);

        assertThat(metadata.lastModifiedAt()).isEqualTo(Instant.parse("2026-01-19T21:00:01Z"));
        assertThat(metadata.sha256()).isEqualTo("482399306951b6ff9e00e3ec72a7eed8d927fb2db4f4e61f2d6218cf67133cc0");
    }

    @Test
    void shouldReturnNullSha256WhenMissing() {
        final NvdDataFeedMetadata metadata = NvdDataFeedMetadata.of("""
                lastModifiedDate:2026-01-19T16:00:01-05:00
                size:15114674
                """);

        assertThat(metadata.lastModifiedAt()).isNotNull();
        assertThat(metadata.sha256()).isNull();
    }

    @Test
    void shouldNormalizeSha256ToLowerCase() {
        final NvdDataFeedMetadata metadata = NvdDataFeedMetadata.of("""
                lastModifiedDate:2026-01-19T16:00:01-05:00
                sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
                """);

        assertThat(metadata.sha256()).isEqualTo("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    }

}
