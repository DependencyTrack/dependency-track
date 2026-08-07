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
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.util.List;

/**
 * Compact cache encoding for Snyk analyzer results.
 * <p>
 * Empty or untrusted outcomes use single-byte sentinels or {@code null} so portfolio-scale
 * cache reads avoid JSON deserialization for the common negative-cache case.
 *
 * @since 5.1.0
 */
final class SnykCacheCodec {

    /** Legacy and coordinates-only negative cache: FULL match, no issues. */
    private static final byte SENTINEL_PARTIAL = 2;
    private static final byte SENTINEL_NONE = 3;

    private SnykCacheCodec() {
    }

    static byte @Nullable [] encode(ObjectMapper objectMapper, SnykCachedPurlResult result) throws IOException {
        if (result.issues() != null && !result.issues().isEmpty()) {
            return objectMapper.writeValueAsBytes(result);
        }
        if (result.matchType() == SnykMatchType.PARTIAL) {
            return new byte[] {SENTINEL_PARTIAL};
        }
        if (result.matchType() == SnykMatchType.NONE) {
            return new byte[] {SENTINEL_NONE};
        }
        // FULL with no issues
        return null;
    }

    static @Nullable SnykCachedPurlResult decode(
            ObjectMapper objectMapper,
            byte @Nullable [] cachedBytes) throws IOException {
        if (cachedBytes == null) {
            return SnykCachedPurlResult.full(List.of());
        }
        if (cachedBytes.length == 1) {
            return switch (cachedBytes[0]) {
                case SENTINEL_PARTIAL -> untrusted(SnykMatchType.PARTIAL);
                case SENTINEL_NONE -> untrusted(SnykMatchType.NONE);
                default -> tryStructuredFormats(objectMapper, cachedBytes);
            };
        }
        return tryStructuredFormats(objectMapper, cachedBytes);
    }

    private static @Nullable SnykCachedPurlResult tryStructuredFormats(
            ObjectMapper objectMapper,
            byte[] cachedBytes) throws IOException {
        try {
            return objectMapper.readValue(cachedBytes, SnykCachedPurlResult.class);
        } catch (IOException ignored) {
            // Fall through to legacy SnykIssue[] format.
        }

        final SnykIssue[] issues = objectMapper.readValue(cachedBytes, SnykIssue[].class);
        return SnykCachedPurlResult.full(List.of(issues));
    }

    private static SnykCachedPurlResult untrusted(SnykMatchType matchType) {
        return new SnykCachedPurlResult(matchType, List.of(), null, null);
    }

}
