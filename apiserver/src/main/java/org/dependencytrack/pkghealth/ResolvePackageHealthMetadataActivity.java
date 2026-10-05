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
package org.dependencytrack.pkghealth;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.persistence.jdbi.PackageHealthMetadataDao;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.client.ApiRateLimitException;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.dependencytrack.proto.internal.workflow.v1.PackageHealthGitHubFetch;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityRes;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Fetches and stores health metadata for one batch of packages.
 * <p>
 * Each package is fetched in two parts: deps.dev, then GitHub. When the GitHub part fails or hits
 * the GitHub rate limit, the deps.dev part is still stored, and the stored GitHub fields are kept.
 * <p>
 * When a rate limit is reached, the packages fetched so far are stored. Packages that still need
 * deps.dev, and packages that only still need GitHub, are returned together with the time the
 * earliest of those limits resets. The workflow waits for that time, so rate limits do not use up
 * retry attempts.
 */
@ActivitySpec(name = "resolve-package-health-metadata", defaultTaskQueue = "package-health-metadata-resolutions")
public final class ResolvePackageHealthMetadataActivity
        implements Activity<ResolvePackageHealthMetadataActivityArg, ResolvePackageHealthMetadataActivityRes> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ResolvePackageHealthMetadataActivity.class);

    private final PackageHealthAnalyzer analyzer;
    private final Clock clock;

    public ResolvePackageHealthMetadataActivity(final PackageHealthAnalyzer analyzer) {
        this(analyzer, Clock.systemUTC());
    }

    ResolvePackageHealthMetadataActivity(final PackageHealthAnalyzer analyzer, final Clock clock) {
        this.analyzer = requireNonNull(analyzer, "analyzer must not be null");
        this.clock = requireNonNull(clock, "clock must not be null");
    }

    @Override
    public @Nullable ResolvePackageHealthMetadataActivityRes execute(
            final ActivityContext ctx, final @Nullable ResolvePackageHealthMetadataActivityArg arg)
            throws InterruptedException, MalformedPackageURLException {
        if (arg == null || (arg.getPurlsCount() == 0 && arg.getGithubFetchesCount() == 0)) {
            return ResolvePackageHealthMetadataActivityRes.getDefaultInstance();
        }

        // The setting can be turned off while a run waits for a rate limit to reset.
        if (!withJdbiHandle(PackageHealthSettings::isEnabled)) {
            LOGGER.info(
                    "Package health metadata resolution is disabled; Skipping {} packages",
                    arg.getPurlsCount() + arg.getGithubFetchesCount());
            return ResolvePackageHealthMetadataActivityRes.getDefaultInstance();
        }

        final var batch = new Batch();

        for (final PackageHealthGitHubFetch fetch : arg.getGithubFetchesList()) {
            final AnalyzedPackageHealth gitHubMetadata = fetchGitHubPart(
                            batch, new PackageURL(fetch.getPurl()), fetch.getRepository())
                    .metadata();
            if (gitHubMetadata != null) {
                batch.gitHubUpdates.add(
                        gitHubMetadata.toMetadata(PackageHealthMetadataStatus.PROCESSED, clock.instant()));
            }
        }

        // Same rule as package metadata resolution: names of internal packages must not leave the server.
        final var internalIdentifier = new InternalComponentIdentifier();

        final List<String> purls = arg.getPurlsList();
        for (int i = 0; i < purls.size(); i++) {
            final var purl = new PackageURL(purls.get(i));
            if (internalIdentifier.isInternal(purl)) {
                batch.metadataToPersist.add(notAvailable(purl));
                continue;
            }

            final PackageHealthAnalyzer.AnalysisResult result;
            try {
                result = analyzer.analyze(purl);
            } catch (PackageHealthAnalyzer.AnalysisException e) {
                if (e.getCause() instanceof ApiRateLimitException rateLimitException) {
                    batch.depsDevRateLimitResetAt = rateLimitException.resetAt();
                    batch.unresolvedPurls = purls.subList(i, purls.size());
                    break;
                }
                // Recorded with a fetch time, so that the package is tried again at its next
                // refresh instead of on every run, and its stored values are kept.
                LOGGER.warn("Failed to resolve health metadata for {}; Skipping it", purl, e);
                batch.failedPurls.add(purl);
                continue;
            }

            if (!(result instanceof PackageHealthAnalyzer.AnalysisResult.Available available)) {
                batch.metadataToPersist.add(notAvailable(purl));
                continue;
            }

            final AnalyzedPackageHealth metadata = available.metadata();
            final String gitHubRepository = available.gitHubRepository();
            if (gitHubRepository != null) {
                final GitHubPart gitHubPart = fetchGitHubPart(batch, metadata.getPurl(), gitHubRepository);
                final AnalyzedPackageHealth gitHubMetadata = gitHubPart.metadata();
                if (!gitHubPart.fetched()) {
                    batch.keepStoredGitHubFields.add(metadata.getPurl().canonicalize());
                } else if (gitHubMetadata != null) {
                    metadata.mergeFrom(gitHubMetadata);
                }
            }
            batch.metadataToPersist.add(metadata.toMetadata(PackageHealthMetadataStatus.PROCESSED, clock.instant()));
        }

        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before package health metadata was stored");
        }

        persist(batch, clock.instant());

        final var result = ResolvePackageHealthMetadataActivityRes.newBuilder()
                .addAllUnresolvedPurls(batch.unresolvedPurls)
                .addAllPendingGithubFetches(batch.pendingGitHubFetches);
        final Instant rateLimitResetAt = earliest(batch.depsDevRateLimitResetAt, batch.gitHubRateLimitResetAt);
        if (rateLimitResetAt != null) {
            result.setRateLimitResetAt(Timestamps.fromMillis(rateLimitResetAt.toEpochMilli()));
        }
        return result.build();
    }

    /**
     * Fetches the GitHub part of a package, unless the GitHub rate limit was already reached in
     * this batch. A rate limited package is added to the pending GitHub fetches.
     */
    private GitHubPart fetchGitHubPart(final Batch batch, final PackageURL packagePurl, final String repository)
            throws InterruptedException {
        final var pendingFetch = PackageHealthGitHubFetch.newBuilder()
                .setPurl(packagePurl.canonicalize())
                .setRepository(repository)
                .build();
        if (batch.gitHubRateLimitResetAt != null) {
            batch.pendingGitHubFetches.add(pendingFetch);
            return GitHubPart.NOT_FETCHED;
        }

        try {
            return new GitHubPart(
                    true,
                    analyzer.analyzeGitHubRepository(packagePurl, repository).orElse(null));
        } catch (PackageHealthAnalyzer.AnalysisException e) {
            if (e.getCause() instanceof ApiRateLimitException rateLimitException) {
                batch.gitHubRateLimitResetAt = rateLimitException.resetAt();
                batch.pendingGitHubFetches.add(pendingFetch);
            } else {
                LOGGER.warn(
                        "Failed to resolve GitHub health metadata for {}; Keeping its stored GitHub data",
                        packagePurl,
                        e);
            }
            return GitHubPart.NOT_FETCHED;
        }
    }

    /**
     * @param fetched  Whether GitHub answered. If not, the stored GitHub fields are kept.
     * @param metadata What GitHub returned. Empty when GitHub is not configured or does not know
     *                 the repository, which clears the stored GitHub fields.
     */
    private record GitHubPart(boolean fetched, @Nullable AnalyzedPackageHealth metadata) {

        private static final GitHubPart NOT_FETCHED = new GitHubPart(false, null);
    }

    private static void persist(final Batch batch, final Instant fetchedAt) {
        if (batch.metadataToPersist.isEmpty() && batch.gitHubUpdates.isEmpty() && batch.failedPurls.isEmpty()) {
            return;
        }

        useJdbiTransaction(handle -> {
            final var dao = new PackageHealthMetadataDao(handle);
            dao.recordFailedFetches(batch.failedPurls, fetchedAt);

            final var purls = new ArrayList<PackageURL>(batch.metadataToPersist.size() + batch.gitHubUpdates.size());
            batch.metadataToPersist.forEach(metadata -> purls.add(metadata.purl()));
            batch.gitHubUpdates.forEach(metadata -> purls.add(metadata.purl()));
            if (purls.isEmpty()) {
                return;
            }
            final Map<String, PackageHealthMetadata> previousByPurl = dao.getAll(purls);

            final var toUpsert = new ArrayList<PackageHealthMetadata>(purls.size());
            for (final PackageHealthMetadata metadata : batch.metadataToPersist) {
                final String packagePurl = metadata.purl().canonicalize();
                final PackageHealthMetadata previous = previousByPurl.get(packagePurl);
                toUpsert.add(
                        previous != null && batch.keepStoredGitHubFields.contains(packagePurl)
                                ? withGitHubFieldsOf(metadata, previous)
                                : metadata);
            }
            for (final PackageHealthMetadata gitHubUpdate : batch.gitHubUpdates) {
                // The deps.dev part was stored by an earlier call. Without it, for example because
                // the package metadata was deleted meanwhile, there is nothing to add to.
                final PackageHealthMetadata previous =
                        previousByPurl.get(gitHubUpdate.purl().canonicalize());
                if (previous != null) {
                    toUpsert.add(withGitHubFieldsOf(previous, gitHubUpdate));
                }
            }
            dao.upsertAll(toUpsert);
        });
    }

    /**
     * @return {@code target} with the fields that GitHub provides taken from {@code source}. deps.dev
     *         also provides open issues and the GitHub URL, so {@code target} keeps those when
     *         {@code source} has none.
     */
    private static PackageHealthMetadata withGitHubFieldsOf(
            final PackageHealthMetadata target, final PackageHealthMetadata source) {
        return new PackageHealthMetadata(
                target.purl(),
                target.stars(),
                target.forks(),
                source.contributors(),
                source.commitFrequencyWeekly(),
                source.openIssues() != null ? source.openIssues() : target.openIssues(),
                source.openPullRequests(),
                source.lastCommit(),
                source.busFactor(),
                source.hasReadme(),
                source.hasCodeOfConduct(),
                source.hasSecurityPolicy(),
                target.dependents(),
                source.files(),
                source.repositoryArchived(),
                target.scorecardScore(),
                target.scorecardReferenceVersion(),
                target.scorecardTimestamp(),
                target.projectMetadataObservedAt(),
                target.depsDevUrl(),
                source.githubUrl() != null ? source.githubUrl() : target.githubUrl(),
                source.averageIssueAgeDays(),
                target.lastFetch(),
                target.status(),
                target.scorecardChecks());
    }

    private static @Nullable Instant earliest(final @Nullable Instant a, final @Nullable Instant b) {
        if (a == null) {
            return b;
        }
        return b == null || a.isBefore(b) ? a : b;
    }

    private PackageHealthMetadata notAvailable(final PackageURL purl) {
        final PackageURL packagePurl =
                requireNonNull(PurlUtil.silentPurlPackageOnly(purl), "Unable to create package-only PURL");
        return new AnalyzedPackageHealth(packagePurl)
                .toMetadata(PackageHealthMetadataStatus.NOT_AVAILABLE, clock.instant());
    }

    private static final class Batch {

        private final List<PackageHealthMetadata> metadataToPersist = new ArrayList<>();
        private final List<PackageHealthMetadata> gitHubUpdates = new ArrayList<>();
        private final List<PackageURL> failedPurls = new ArrayList<>();
        private final Set<String> keepStoredGitHubFields = new HashSet<>();
        private final List<PackageHealthGitHubFetch> pendingGitHubFetches = new ArrayList<>();
        private List<String> unresolvedPurls = List.of();
        private @Nullable Instant depsDevRateLimitResetAt;
        private @Nullable Instant gitHubRateLimitResetAt;
    }
}
