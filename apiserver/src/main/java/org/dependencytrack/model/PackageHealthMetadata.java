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
package org.dependencytrack.model;

import com.github.packageurl.PackageURL;
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Represents health metadata collected for a package.
 *
 * @since 5.2.0
 */
@NullMarked
public record PackageHealthMetadata(
        PackageURL purl,
        @Nullable Long stars,
        @Nullable Long forks,
        @Nullable Long contributors,
        @Nullable Float commitFrequencyWeekly,
        @Nullable Long openIssues,
        @Nullable Long openPullRequests,
        @Nullable Instant lastCommit,
        @Nullable Integer busFactor,
        @Nullable Boolean hasReadme,
        @Nullable Boolean hasCodeOfConduct,
        @Nullable Boolean hasSecurityPolicy,
        @Nullable Long dependents,
        @Nullable Long files,
        @Nullable Boolean repositoryArchived,
        @Nullable Float scorecardScore,
        @Nullable String scorecardReferenceVersion,
        @Nullable Instant scorecardTimestamp,
        @Nullable Instant projectMetadataObservedAt,
        @Nullable String depsDevUrl,
        @Nullable String githubUrl,
        @Nullable Float averageIssueAgeDays,
        @Nullable Instant lastFetch,
        PackageHealthMetadataStatus status,
        List<PackageHealthScorecardCheck> scorecardChecks) {

    public PackageHealthMetadata {
        PurlUtil.requirePackageOnly(requireNonNull(purl, "purl must not be null"));
        requireNonNull(status, "status must not be null");
        requireNonNull(scorecardChecks, "scorecardChecks must not be null");

        for (final PackageHealthScorecardCheck check : scorecardChecks) {
            if (!purl.equals(check.purl())) {
                throw new IllegalArgumentException("scorecard check purl must match health metadata purl");
            }
        }

        scorecardChecks = List.copyOf(scorecardChecks);
    }
}
