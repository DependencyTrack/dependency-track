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
package org.dependencytrack.pkghealth.model;

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.List;

import static java.util.Objects.requireNonNull;

@NullMarked
public final class AnalyzedPackageHealth {

    private final PackageURL purl;

    private @Nullable Long stars;
    private @Nullable Long forks;
    private @Nullable Long contributors;
    private @Nullable Float commitFrequencyWeekly;
    private @Nullable Long openIssues;
    private @Nullable Long openPullRequests;
    private @Nullable Instant lastCommit;
    private @Nullable Integer busFactor;
    private @Nullable Boolean hasReadme;
    private @Nullable Boolean hasCodeOfConduct;
    private @Nullable Boolean hasSecurityPolicy;
    private @Nullable Long dependents;
    private @Nullable Long files;
    private @Nullable Boolean repositoryArchived;
    private @Nullable Float scorecardScore;
    private @Nullable String scorecardReferenceVersion;
    private @Nullable Instant scorecardTimestamp;
    private @Nullable Instant projectMetadataObservedAt;
    private @Nullable String depsDevUrl;
    private @Nullable String githubUrl;
    private @Nullable Float averageIssueAgeDays;

    private List<PackageHealthScorecardCheck> scorecardChecks = List.of();

    public AnalyzedPackageHealth(PackageURL purl) {
        PurlUtil.requirePackageOnly(requireNonNull(purl, "purl must not be null"));
        this.purl = purl;
    }

    public PackageHealthMetadata toMetadata(final PackageHealthMetadataStatus status, final Instant lastFetch) {
        return new PackageHealthMetadata(
                purl,
                stars,
                forks,
                contributors,
                commitFrequencyWeekly,
                openIssues,
                openPullRequests,
                lastCommit,
                busFactor,
                hasReadme,
                hasCodeOfConduct,
                hasSecurityPolicy,
                dependents,
                files,
                repositoryArchived,
                scorecardScore,
                scorecardReferenceVersion,
                scorecardTimestamp,
                projectMetadataObservedAt,
                depsDevUrl,
                githubUrl,
                averageIssueAgeDays,
                requireNonNull(lastFetch, "lastFetch must not be null"),
                requireNonNull(status, "status must not be null"),
                scorecardChecks);
    }

    public void mergeFrom(AnalyzedPackageHealth other) {
        requireNonNull(other, "other must not be null");

        if (!purl.equals(other.purl)) {
            throw new IllegalArgumentException("Can not merge health metadata for different PURLs");
        }

        if (other.stars != null) {
            stars = other.stars;
        }
        if (other.forks != null) {
            forks = other.forks;
        }
        if (other.contributors != null) {
            contributors = other.contributors;
        }
        if (other.commitFrequencyWeekly != null) {
            commitFrequencyWeekly = other.commitFrequencyWeekly;
        }
        if (other.openIssues != null) {
            openIssues = other.openIssues;
        }
        if (other.openPullRequests != null) {
            openPullRequests = other.openPullRequests;
        }
        if (other.lastCommit != null) {
            lastCommit = other.lastCommit;
        }
        if (other.busFactor != null) {
            busFactor = other.busFactor;
        }
        if (other.hasReadme != null) {
            hasReadme = other.hasReadme;
        }
        if (other.hasCodeOfConduct != null) {
            hasCodeOfConduct = other.hasCodeOfConduct;
        }
        if (other.hasSecurityPolicy != null) {
            hasSecurityPolicy = other.hasSecurityPolicy;
        }
        if (other.dependents != null) {
            dependents = other.dependents;
        }
        if (other.files != null) {
            files = other.files;
        }
        if (other.repositoryArchived != null) {
            repositoryArchived = other.repositoryArchived;
        }
        if (other.scorecardScore != null) {
            scorecardScore = other.scorecardScore;
        }
        if (other.scorecardReferenceVersion != null) {
            scorecardReferenceVersion = other.scorecardReferenceVersion;
        }
        if (other.scorecardTimestamp != null) {
            scorecardTimestamp = other.scorecardTimestamp;
        }
        if (other.projectMetadataObservedAt != null) {
            projectMetadataObservedAt = other.projectMetadataObservedAt;
        }
        if (other.depsDevUrl != null) {
            depsDevUrl = other.depsDevUrl;
        }
        if (other.githubUrl != null) {
            githubUrl = other.githubUrl;
        }
        if (other.averageIssueAgeDays != null) {
            averageIssueAgeDays = other.averageIssueAgeDays;
        }
        if (!other.scorecardChecks.isEmpty()) {
            scorecardChecks = other.scorecardChecks;
        }
    }

    public PackageURL getPurl() {
        return purl;
    }

    public @Nullable Long getStars() {
        return stars;
    }

    public @Nullable Long getForks() {
        return forks;
    }

    public @Nullable Long getContributors() {
        return contributors;
    }

    public @Nullable Float getCommitFrequencyWeekly() {
        return commitFrequencyWeekly;
    }

    public @Nullable Long getOpenIssues() {
        return openIssues;
    }

    public @Nullable Long getOpenPullRequests() {
        return openPullRequests;
    }

    public @Nullable Instant getLastCommit() {
        return lastCommit;
    }

    public @Nullable Integer getBusFactor() {
        return busFactor;
    }

    public @Nullable Boolean getHasReadme() {
        return hasReadme;
    }

    public @Nullable Boolean getHasCodeOfConduct() {
        return hasCodeOfConduct;
    }

    public @Nullable Boolean getHasSecurityPolicy() {
        return hasSecurityPolicy;
    }

    public @Nullable Long getDependents() {
        return dependents;
    }

    public @Nullable Long getFiles() {
        return files;
    }

    public @Nullable Boolean getRepositoryArchived() {
        return repositoryArchived;
    }

    public @Nullable Float getScorecardScore() {
        return scorecardScore;
    }

    public @Nullable String getScorecardReferenceVersion() {
        return scorecardReferenceVersion;
    }

    public @Nullable Instant getScorecardTimestamp() {
        return scorecardTimestamp;
    }

    public @Nullable Instant getProjectMetadataObservedAt() {
        return projectMetadataObservedAt;
    }

    public @Nullable String getDepsDevUrl() {
        return depsDevUrl;
    }

    public @Nullable String getGithubUrl() {
        return githubUrl;
    }

    public @Nullable Float getAverageIssueAgeDays() {
        return averageIssueAgeDays;
    }

    public List<PackageHealthScorecardCheck> getScorecardChecks() {
        return scorecardChecks;
    }

    public void setStars(@Nullable Long stars) {
        this.stars = stars;
    }

    public void setForks(@Nullable Long forks) {
        this.forks = forks;
    }

    public void setContributors(@Nullable Long contributors) {
        this.contributors = contributors;
    }

    public void setCommitFrequencyWeekly(@Nullable Float commitFrequencyWeekly) {
        this.commitFrequencyWeekly = commitFrequencyWeekly;
    }

    public void setOpenIssues(@Nullable Long openIssues) {
        this.openIssues = openIssues;
    }

    public void setOpenPullRequests(@Nullable Long openPullRequests) {
        this.openPullRequests = openPullRequests;
    }

    public void setLastCommit(@Nullable Instant lastCommit) {
        this.lastCommit = lastCommit;
    }

    public void setBusFactor(@Nullable Integer busFactor) {
        this.busFactor = busFactor;
    }

    public void setHasReadme(@Nullable Boolean hasReadme) {
        this.hasReadme = hasReadme;
    }

    public void setHasCodeOfConduct(@Nullable Boolean hasCodeOfConduct) {
        this.hasCodeOfConduct = hasCodeOfConduct;
    }

    public void setHasSecurityPolicy(@Nullable Boolean hasSecurityPolicy) {
        this.hasSecurityPolicy = hasSecurityPolicy;
    }

    public void setDependents(@Nullable Long dependents) {
        this.dependents = dependents;
    }

    public void setFiles(@Nullable Long files) {
        this.files = files;
    }

    public void setRepositoryArchived(@Nullable Boolean repositoryArchived) {
        this.repositoryArchived = repositoryArchived;
    }

    public void setScorecardScore(@Nullable Float scorecardScore) {
        this.scorecardScore = scorecardScore;
    }

    @Override
    public String toString() {
        return "AnalyzedPackageHealth{" + "purl="
                + purl + ", stars="
                + stars + ", forks="
                + forks + ", contributors="
                + contributors + ", commitFrequencyWeekly="
                + commitFrequencyWeekly + ", openIssues="
                + openIssues + ", openPullRequests="
                + openPullRequests + ", lastCommit="
                + lastCommit + ", busFactor="
                + busFactor + ", hasReadme="
                + hasReadme + ", hasCodeOfConduct="
                + hasCodeOfConduct + ", hasSecurityPolicy="
                + hasSecurityPolicy + ", dependents="
                + dependents + ", files="
                + files + ", repositoryArchived="
                + repositoryArchived + ", scorecardScore="
                + scorecardScore + ", scorecardReferenceVersion='"
                + scorecardReferenceVersion + '\'' + ", scorecardTimestamp="
                + scorecardTimestamp + ", projectMetadataObservedAt="
                + projectMetadataObservedAt + ", depsDevUrl='"
                + depsDevUrl + '\'' + ", githubUrl='"
                + githubUrl + '\'' + ", averageIssueAgeDays="
                + averageIssueAgeDays + ", scorecardChecks="
                + scorecardChecks + '}';
    }

    public void setScorecardReferenceVersion(@Nullable String scorecardReferenceVersion) {
        this.scorecardReferenceVersion = scorecardReferenceVersion;
    }

    public void setScorecardTimestamp(@Nullable Instant scorecardTimestamp) {
        this.scorecardTimestamp = scorecardTimestamp;
    }

    public void setProjectMetadataObservedAt(@Nullable Instant projectMetadataObservedAt) {
        this.projectMetadataObservedAt = projectMetadataObservedAt;
    }

    public void setDepsDevUrl(@Nullable String depsDevUrl) {
        this.depsDevUrl = depsDevUrl;
    }

    public void setGithubUrl(@Nullable String githubUrl) {
        this.githubUrl = githubUrl;
    }

    public void setAverageIssueAgeDays(@Nullable Float averageIssueAgeDays) {
        this.averageIssueAgeDays = averageIssueAgeDays;
    }

    public void setScorecardChecks(List<PackageHealthScorecardCheck> scorecardChecks) {
        this.scorecardChecks = List.copyOf(requireNonNull(scorecardChecks, "scorecardChecks must not be null"));
    }
}
