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

import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Cached Snyk analysis result for a single request PURL when findings are present.
 * <p>
 * Outcomes with no findings (including {@link SnykMatchType#NONE}, empty
 * {@link SnykMatchType#FULL}, and empty {@link SnykMatchType#PARTIAL}) are cached as
 * {@code null} and do not use this type.
 * <p>
 * {@link SnykMatchType#PARTIAL} may still include issues (name/version matched, checksum
 * did not); those are cached here with {@code matchType = PARTIAL} so cache hits retain
 * findings without re-fetching.
 *
 * @since 5.1.0
 */
record SnykCachedPurlResult(
        SnykMatchType matchType,
        @Nullable List<SnykIssue> issues,
        @Nullable Boolean nameVersionMatched,
        @Nullable Boolean checksumMatched) {

    /**
     * Coordinates-only or legacy cache entry with findings: name/version matched,
     * no checksum in the request ({@code checksumMatched = null}).
     */
    static SnykCachedPurlResult full(@Nullable List<SnykIssue> issues) {
        return new SnykCachedPurlResult(SnykMatchType.FULL, issues, true, null);
    }

    static SnykCachedPurlResult of(
            SnykMatchType matchType,
            @Nullable List<SnykIssue> issues,
            SnykIssuesMeta.@Nullable Match match) {
        Boolean nameVersion = null;
        Boolean checksum = null;
        if (match != null && match.details() != null) {
            nameVersion = match.details().nameVersion();
            checksum = match.details().checksum();
        }
        return new SnykCachedPurlResult(matchType, issues, nameVersion, checksum);
    }

}
