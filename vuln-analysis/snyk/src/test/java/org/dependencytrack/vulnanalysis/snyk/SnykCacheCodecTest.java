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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SnykCacheCodecTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void shouldEncodeFullNegativeAsNull() throws Exception {
        assertThat(SnykCacheCodec.encode(objectMapper, SnykCachedPurlResult.full(List.of()))).isNull();
    }

    @Test
    void shouldEncodePartialAndNoneAsSingleByteSentinels() throws Exception {
        assertThat(SnykCacheCodec.encode(objectMapper,
                new SnykCachedPurlResult(SnykMatchType.PARTIAL, List.of(), null, null)))
                .isEqualTo(new byte[] {2});
        assertThat(SnykCacheCodec.encode(objectMapper,
                new SnykCachedPurlResult(SnykMatchType.NONE, List.of(), null, null)))
                .isEqualTo(new byte[] {3});
    }

    @Test
    void shouldDecodeSentinelsWithoutJson() throws Exception {
        assertThat(SnykCacheCodec.decode(objectMapper, null).matchType()).isEqualTo(SnykMatchType.FULL);
        assertThat(SnykCacheCodec.decode(objectMapper, new byte[] {2}).matchType()).isEqualTo(SnykMatchType.PARTIAL);
        assertThat(SnykCacheCodec.decode(objectMapper, new byte[] {3}).matchType()).isEqualTo(SnykMatchType.NONE);
    }

}
